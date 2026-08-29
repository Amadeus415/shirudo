#!/usr/bin/env python3
"""Generate traffic that exercises the combined Linux observability upatch."""

import argparse
import os
import random
import socket
import struct
import subprocess
import threading


def exec_event():
    subprocess.run(["/bin/true"], check=True)


def tcp_event():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted = []

    def accept_one():
        conn, _ = server.accept()
        accepted.append(conn.recv(1))
        conn.close()

    thread = threading.Thread(target=accept_one)
    thread.start()
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(b"o")
    client.close()
    thread.join(3)
    server.close()
    if thread.is_alive() or not accepted:
        raise RuntimeError("TCP listener did not receive the test connection")


def udp_event():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    destination = receiver.getsockname()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"obs", destination)
    receiver.settimeout(3)
    payload, _ = receiver.recvfrom(16)
    sender.close()
    receiver.close()
    if payload != b"obs":
        raise RuntimeError("UDP listener received an unexpected payload")


def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def dns_event():
    nameservers = []
    with open("/etc/resolv.conf", encoding="utf-8") as resolv:
        for line in resolv:
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                nameservers.append(fields[1])
    if not nameservers:
        raise RuntimeError("/etc/resolv.conf has no nameserver")

    transaction = random.randrange(1, 65535)
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0)
    query += dns_name("example.com") + struct.pack("!HH", 1, 1)
    last_error = None
    for nameserver in nameservers:
        family = socket.AF_INET6 if ":" in nameserver else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(4)
        try:
            sock.sendto(query, (nameserver, 53))
            response, _ = sock.recvfrom(4096)
            if len(response) < 12 or struct.unpack("!H", response[:2])[0] != transaction:
                raise RuntimeError("DNS response transaction ID mismatch")
            if not (struct.unpack("!H", response[2:4])[0] & 0x8000):
                raise RuntimeError("DNS response flag is not set")
            return
        except (OSError, RuntimeError) as error:
            last_error = error
        finally:
            sock.close()
    raise RuntimeError(f"DNS query failed: {last_error}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("all", "exec", "tcp", "udp", "dns"))
    mode = parser.parse_args().mode
    if mode in ("all", "exec"):
        exec_event()
    if mode in ("all", "tcp"):
        tcp_event()
    if mode in ("all", "udp"):
        udp_event()
    if mode in ("all", "dns"):
        dns_event()


if __name__ == "__main__":
    main()
