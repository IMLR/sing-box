#!/usr/bin/env python3
"""Exercise the built core on loopback, without changing host routing."""

import contextlib
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def available_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        result += chunk
    return result


def socks_command(port, command, destination):
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00"
        sock.sendall(b"\x05" + bytes([command]) + b"\x00\x01"
                     + socket.inet_aton("127.0.0.1") + struct.pack("!H", destination))
        header = receive(sock, 4)
        assert header[:2] == b"\x05\x00", header
        if header[3] == 1:
            address = socket.inet_ntoa(receive(sock, 4))
        elif header[3] == 4:
            address = socket.inet_ntop(socket.AF_INET6, receive(sock, 16))
        else:
            address = receive(sock, receive(sock, 1)[0]).decode()
        relay_port = struct.unpack("!H", receive(sock, 2))[0]
        return sock, ("127.0.0.1" if address in ("0.0.0.0", "::") else address, relay_port)
    except BaseException:
        sock.close()
        raise


class EchoServers:
    def __enter__(self):
        self.tcp = socket.socket()
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen()
        self.tcp.settimeout(0.2)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(0.2)
        self.stopped = threading.Event()
        self.workers = [threading.Thread(target=self.tcp_loop), threading.Thread(target=self.udp_loop)]
        for worker in self.workers:
            worker.start()
        return self

    def tcp_loop(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(3)
                try:
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                        conn.sendall(data)
                except (OSError, TimeoutError):
                    pass

    def udp_loop(self):
        while not self.stopped.is_set():
            try:
                data, address = self.udp.recvfrom(65536)
                self.udp.sendto(data, address)
            except socket.timeout:
                continue

    def __exit__(self, *_):
        self.stopped.set()
        for worker in self.workers:
            worker.join(timeout=4)
        self.tcp.close()
        self.udp.close()


class Core:
    def __init__(self, binary, path, config):
        self.binary, self.path = binary, path
        self.path.write_text(json.dumps(config))
        self.log = open(path.with_suffix(".log"), "w+")
        self.process = None

    def start(self):
        self.process = subprocess.Popen([self.binary, "run", "-c", str(self.path)],
                                        stdout=self.log, stderr=self.log)
        time.sleep(0.2)
        if self.process.poll() is not None:
            self.log.seek(0)
            raise RuntimeError(self.log.read())

    def stop(self, abrupt=False):
        if self.process and self.process.poll() is None:
            self.process.kill() if abrupt else self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def close(self):
        self.stop()
        self.log.close()


def check_tcp(client_port, target_port):
    conn, _ = socks_command(client_port, 1, target_port)
    with conn:
        payload = b"hysteria TCP echo\x00" * 4096
        conn.sendall(payload)
        assert receive(conn, len(payload)) == payload


def check_udp(sock, relay, target_port):
    header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port)
    for size in (64, 1300, 4096):
        payload = bytes([size % 251]) * size
        sock.sendto(header + payload, relay)
        data, _ = sock.recvfrom(65536)
        assert data == header + payload, (len(data), size)


def run_case(binary, root, echo, mode):
    server_port = available_port(socket.SOCK_DGRAM)
    client_port = available_port(socket.SOCK_STREAM)
    inbound = {"type": "hysteria2", "listen": "127.0.0.1", "listen_port": server_port,
               "users": [{"password": "loopback-test"}],
               "tls": {"enabled": True, "certificate_path": str(root / "cert.pem"),
                       "key_path": str(root / "key.pem")}}
    outbound = {"type": "hysteria2", "tag": "proxy", "server": "127.0.0.1",
                "server_ports": [f"{server_port}:{server_port}"], "hop_interval": "5s",
                "hop_interval_max": "6s", "password": "loopback-test",
                "tls": {"enabled": True, "server_name": "localhost", "insecure": True}}
    if mode != "plain":
        inbound["obfs"] = outbound["obfs"] = {"type": mode, "password": "loopback-obfs"}
    with contextlib.ExitStack() as stack:
        server = Core(binary, root / f"{mode}-server.json",
                      {"log": {"level": "error"}, "inbounds": [inbound],
                       "outbounds": [{"type": "direct", "tag": "direct"}]})
        client = Core(binary, root / f"{mode}-client.json",
                      {"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                       "listen_port": client_port}], "outbounds": [outbound]})
        stack.callback(server.close)
        stack.callback(client.close)
        server.start()
        client.start()
        check_tcp(client_port, echo.tcp.getsockname()[1])
        control, relay = socks_command(client_port, 3, 0)
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            check_udp(udp, relay, echo.udp.getsockname()[1])
            time.sleep(6.5)  # Cross an actual randomized port-hop timer.
            check_udp(udp, relay, echo.udp.getsockname()[1])
            check_tcp(client_port, echo.tcp.getsockname()[1])
        server.stop(abrupt=True)
        server.start()
        deadline = time.monotonic() + 45
        while True:
            try:
                check_tcp(client_port, echo.tcp.getsockname()[1])
                break
            except (OSError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)
        control, relay = socks_command(client_port, 3, 0)
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            check_udp(udp, relay, echo.udp.getsockname()[1])
        print(f"PASS {mode}: TCP, UDP, randomized hopping, reconnect after server termination", flush=True)


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="ax3600-hysteria-") as directory, EchoServers() as echo:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
                        "-subj", "/CN=localhost", "-days", "1"], check=True, capture_output=True)
        for mode in ("plain", "gecko"):
            run_case(binary, root, echo, mode)


if __name__ == "__main__":
    main()
