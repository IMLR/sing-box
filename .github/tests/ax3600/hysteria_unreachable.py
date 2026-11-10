#!/usr/bin/env python3
"""After a brief outage, Hysteria with port hopping must work again at once.

On the router a PPPoE redial left Hysteria unusable for about a minute after
the line was back: the port-hopping receiver stopped at the first port
unreachable and the socket kept sending while nobody read it. Here the
server goes away for three seconds while traffic flows, so the kernel answers
the client with that same ICMP error, then comes back on the same port; the
time until a new connection through the proxy works is measured.

Usage: hysteria_unreachable.py <sing-box binary>
"""

import contextlib
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

from hysteria_eio import keep_sending
from hysteria_smoke import Core, EchoServers, available_port, check_tcp

RECOVERY_LIMIT = 10


def run_case(binary, root, echo, name, obfs):
    server_port = available_port(socket.SOCK_DGRAM)
    client_port = available_port(socket.SOCK_STREAM)
    inbound = {"type": "hysteria2", "listen": "127.0.0.1", "listen_port": server_port,
               "users": [{"password": "loopback-test"}],
               "tls": {"enabled": True, "certificate_path": str(root / "cert.pem"),
                       "key_path": str(root / "key.pem")}}
    # one port, a hop far away: only the receiver itself can bring it back quickly
    outbound = {"type": "hysteria2", "tag": "proxy", "server": "127.0.0.1",
                "server_ports": [f"{server_port}:{server_port}"], "hop_interval": "120s",
                "password": "loopback-test",
                "tls": {"enabled": True, "server_name": "localhost", "insecure": True}}
    if obfs:
        inbound["obfs"] = outbound["obfs"] = {"type": obfs, "password": "loopback-obfs"}
    with contextlib.ExitStack() as stack:
        server = Core(binary, root / f"{name}-server.json",
                      {"log": {"level": "error"}, "inbounds": [inbound],
                       "outbounds": [{"type": "direct", "tag": "direct"}]})
        client = Core(binary, root / f"{name}-client.json",
                      {"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                       "listen_port": client_port}], "outbounds": [outbound]})
        stack.callback(server.close)
        stack.callback(client.close)
        server.start()
        client.start()
        target = echo.tcp.getsockname()[1]
        check_tcp(client_port, target)

        stopped = threading.Event()
        sender = threading.Thread(target=keep_sending, args=(client_port, target, stopped))
        sender.start()
        time.sleep(1)
        server.stop(abrupt=True)
        time.sleep(3)
        server.start()
        back = time.monotonic()
        stopped.set()
        sender.join(timeout=30)

        recovered = None
        while time.monotonic() - back < 90:
            try:
                check_tcp(client_port, target)
                recovered = time.monotonic() - back
                break
            except (OSError, AssertionError, ConnectionError):
                time.sleep(0.5)
        ok = recovered is not None and recovered <= RECOVERY_LIMIT
        print(f"{'PASS' if ok else 'FAIL'} {name}: after the server was unreachable for three seconds, a new "
              f"connection through the proxy works {'again after %.1fs' % recovered if recovered is not None else 'not within 90s'}",
              flush=True)
        return ok


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="ax3600-unreachable-") as directory, EchoServers() as echo:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
                        "-subj", "/CN=localhost", "-days", "1"], check=True, capture_output=True)
        results = [run_case(binary, root, echo, "hopping", None),
                   run_case(binary, root, echo, "hopping-salamander", "salamander")]
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
