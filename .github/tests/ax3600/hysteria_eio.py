#!/usr/bin/env python3
"""A send that fails with EIO must not leave the core spinning.

On the router a PPPoE redial tore the interface down while a QUIC packet was
being sent; that one sendmsg failed with EIO and the core sent empty datagrams
in a loop for 46 hours. Here strace injects that single failure into the
client's sends while traffic flows, then the client's CPU, the datagram rate
and a fresh connection through the proxy are checked.

Needs strace and ptrace permission. Usage: hysteria_eio.py <sing-box binary>
"""

import contextlib
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from hysteria_smoke import Core, EchoServers, available_port, check_tcp, check_udp, socks_command

TICKS = os.sysconf("SC_CLK_TCK")


def cpu_seconds(pid):
    fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / TICKS


def datagrams_sent():
    lines = [l.split() for l in pathlib.Path("/proc/net/snmp").read_text().splitlines() if l.startswith("Udp:")]
    return int(lines[1][lines[0].index("OutDatagrams")])


def measure(pid, seconds):
    cpu, sent, start = cpu_seconds(pid), datagrams_sent(), time.monotonic()
    time.sleep(seconds)
    elapsed = time.monotonic() - start
    return (cpu_seconds(pid) - cpu) / elapsed * 100, (datagrams_sent() - sent) / elapsed


def keep_sending(client_port, target_port, stopped):
    """Keep the QUIC connection busy, so the injected failure hits a real send."""
    while not stopped.is_set():
        with contextlib.suppress(OSError, AssertionError, ConnectionError):
            check_tcp(client_port, target_port)


def inject_eio(pid):
    """Fail the next sendmsg/sendto of every thread of pid once with EIO."""
    tracer = subprocess.Popen(
        ["strace", "-f", "-qq", "-p", str(pid), "-e", "trace=sendmsg,sendto",
         "-e", "inject=sendmsg,sendto:error=EIO:when=1", "-o", "/dev/null"])
    time.sleep(1.5)
    tracer.send_signal(signal.SIGINT)
    tracer.wait(timeout=10)


def run_case(binary, root, echo, name, hopping, gso):
    os.environ["QUIC_GO_DISABLE_GSO"] = "false" if gso else "true"
    server_port = available_port(socket.SOCK_DGRAM)
    client_port = available_port(socket.SOCK_STREAM)
    inbound = {"type": "hysteria2", "listen": "127.0.0.1", "listen_port": server_port,
               "users": [{"password": "loopback-test"}],
               "tls": {"enabled": True, "certificate_path": str(root / "cert.pem"),
                       "key_path": str(root / "key.pem")}}
    outbound = {"type": "hysteria2", "tag": "proxy", "server": "127.0.0.1", "password": "loopback-test",
                "tls": {"enabled": True, "server_name": "localhost", "insecure": True}}
    if hopping:
        outbound.update({"server_ports": [f"{server_port}:{server_port}"], "hop_interval": "30s"})
    else:
        outbound["server_port"] = server_port
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
        check_tcp(client_port, echo.tcp.getsockname()[1])

        stopped = threading.Event()
        sender = threading.Thread(target=keep_sending, args=(client_port, echo.tcp.getsockname()[1], stopped))
        sender.start()
        time.sleep(1)
        inject_eio(client.process.pid)
        stopped.set()
        sender.join(timeout=10)

        time.sleep(3)
        cpu, rate = measure(client.process.pid, 5)
        spinning = cpu > 50 or rate > 5000

        deadline, recovered = time.monotonic() + 30, False
        while time.monotonic() < deadline and not recovered:
            try:
                check_tcp(client_port, echo.tcp.getsockname()[1])
                control, relay = socks_command(client_port, 3, 0)
                with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(3)
                    check_udp(udp, relay, echo.udp.getsockname()[1])
                recovered = True
            except (OSError, AssertionError, ConnectionError):
                time.sleep(0.5)

        verdict = "PASS" if recovered and not spinning else "FAIL"
        print(f"{verdict} {name}: after one EIO the client used {cpu:.0f}% CPU and sent "
              f"{rate:.0f} datagrams/s; new TCP and UDP through the proxy "
              f"{'work' if recovered else 'fail'}", flush=True)
        return verdict == "PASS"


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="ax3600-eio-") as directory, EchoServers() as echo:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
                        "-subj", "/CN=localhost", "-days", "1"], check=True, capture_output=True)
        results = [run_case(binary, root, echo, "no-gso", hopping=False, gso=False),
                   run_case(binary, root, echo, "no-gso-hopping", hopping=True, gso=False),
                   run_case(binary, root, echo, "gso", hopping=False, gso=True)]
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
