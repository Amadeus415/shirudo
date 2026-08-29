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
    labels = [label.encode() for label in name.split(".")]
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("DNS labels must contain between 1 and 63 bytes")
    wire = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    if len(wire) > 255:
        raise ValueError("DNS wire name exceeds 255 bytes")
    return wire


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


def dns_long_event():
    name = ".".join(["a"] * 127)
    transaction = random.randrange(1, 65535)
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
    errors = []

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(3)
    server.bind(("127.0.0.1", 53))

    def answer_one():
        try:
            request, peer = server.recvfrom(4096)
            if request != query:
                raise RuntimeError("local DNS server received an unexpected query")
            header = struct.pack("!HHHHHH", transaction, 0x8180, 1, 1, 0, 0)
            answer = b"\xc0\x0c" + struct.pack(
                "!HHIH4s", 1, 1, 60, 4, socket.inet_aton("203.0.113.10")
            )
            server.sendto(header + question + answer, peer)
        except Exception as error:  # Propagate server-thread failures below.
            errors.append(error)

    thread = threading.Thread(target=answer_one)
    thread.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    try:
        client.sendto(query, ("127.0.0.1", 53))
        response, _ = client.recvfrom(4096)
        if len(response) < 12 or struct.unpack("!H", response[:2])[0] != transaction:
            raise RuntimeError("local DNS response transaction ID mismatch")
    finally:
        client.close()
        thread.join(3)
        server.close()
    if thread.is_alive():
        raise RuntimeError("local DNS server did not finish")
    if errors:
        raise RuntimeError(f"local DNS server failed: {errors[0]}")


def dns_many_answers_event():
    name = "many.example"
    transaction = random.randrange(1, 65535)
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
    errors = []

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(3)
    server.bind(("127.0.0.1", 53))

    def answer_one():
        try:
            request, peer = server.recvfrom(4096)
            if request != query:
                raise RuntimeError("local DNS server received an unexpected query")
            header = struct.pack("!HHHHHH", transaction, 0x8180, 1, 75, 0, 0)
            unsupported = b"\xc0\x0c" + struct.pack("!HHIHB", 16, 1, 60, 1, 0)
            answer = b"\xc0\x0c" + struct.pack(
                "!HHIH4s", 1, 1, 60, 4, socket.inet_aton("203.0.113.75")
            )
            server.sendto(header + question + unsupported * 74 + answer, peer)
        except Exception as error:  # Propagate server-thread failures below.
            errors.append(error)

    thread = threading.Thread(target=answer_one)
    thread.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    try:
        client.sendto(query, ("127.0.0.1", 53))
        response, _ = client.recvfrom(4096)
        if len(response) < 12 or struct.unpack("!H", response[:2])[0] != transaction:
            raise RuntimeError("local DNS response transaction ID mismatch")
    finally:
        client.close()
        thread.join(3)
        server.close()
    if thread.is_alive():
        raise RuntimeError("local DNS server did not finish")
    if errors:
        raise RuntimeError(f"local DNS server failed: {errors[0]}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=("all", "exec", "tcp", "udp", "dns", "dns-long", "dns-many"),
    )
    mode = parser.parse_args().mode
    if mode in ("all", "exec"):
        exec_event()
    if mode in ("all", "tcp"):
        tcp_event()
    if mode in ("all", "udp"):
        udp_event()
    if mode in ("all", "dns"):
        dns_event()
    if mode == "dns-long":
        dns_long_event()
    if mode == "dns-many":
        dns_many_answers_event()


if __name__ == "__main__":
    main()
