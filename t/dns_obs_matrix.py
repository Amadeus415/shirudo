#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the loaded Linux-observability DNS programs with exact frames."""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


BATCH_MAGIC = 0x31534E44
BATCH_VERSION = 1
QUERY = 0
RESPONSE = 1
A = 1
AAAA = 28
IN = 1

COUNTERS = (
    "QUERY_PACKET",
    "QUERY_NO_UID",
    "QUERY_HDR_FAIL",
    "QUERY_IS_RESPONSE",
    "QUERY_QDCOUNT_BAD",
    "QUERY_SCRATCH_MISS",
    "QUERY_NAME_FAIL",
    "QUERY_EMPTY_NAME",
    "QUERY_QTYPE_READ_FAIL",
    "QUERY_QTYPE_UNSUPPORTED",
    "QUERY_STORED",
    "RESP_PACKET",
    "RESP_HDR_FAIL",
    "RESP_NOT_RESPONSE",
    "RESP_QDCOUNT_BAD",
    "RESP_NO_ANSWER",
    "RESP_REQ_MISS",
    "RESP_QNAME_SKIP_FAIL",
    "RESP_QTYPE_READ_FAIL",
    "RESP_QTYPE_MISMATCH",
    "RESP_ANSWER_SEEN",
    "RESP_ANSWER_SKIP_FAIL",
    "RESP_RR_READ_FAIL",
    "RESP_RDATA_BOUNDS_FAIL",
    "RESP_ADDR_UNSUPPORTED",
    "RESP_ADDR_PARSED",
    "RESP_TOUCH",
    "RESP_DELETE",
    "TOUCH_CALLED",
    "TOUCH_INIT_FAIL",
    "TOUCH_HIT",
    "ALLOC_ATTEMPT",
    "ALLOC_BAD_IDX",
    "ALLOC_OK",
    "ALLOC_ENTRY_MISS",
    "CAS_OK",
    "CAS_FAIL",
    "PACKET_IPV4",
    "PACKET_IPV6",
    "PACKET_NOT_UDP",
    "PACKET_PORT_SKIP",
)
COUNTER = {name: index for index, name in enumerate(COUNTERS)}

# These depend on unavailable task state, arena exhaustion, or races and are
# intentionally outside the deterministic packet-controlled coverage set.
NON_PACKET_COUNTERS = {
    "QUERY_NO_UID",
    "QUERY_SCRATCH_MISS",
    "TOUCH_INIT_FAIL",
    "ALLOC_BAD_IDX",
    "ALLOC_ENTRY_MISS",
    "CAS_FAIL",
}


@dataclass
class Case:
    name: str
    direction: int
    txid: int
    frame: bytes
    counters: dict[str, int] = field(default_factory=dict)
    request: bool | None = False
    request_name: str | None = None
    request_qtype: int | None = None
    run_rc: int = 0
    retval: int = 1


def wire_name(name: str | list[bytes]) -> bytes:
    labels = [part.encode("ascii") for part in name.split(".")] if isinstance(name, str) else name
    return b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"


def dns_header(txid: int, flags: int, qdcount: int, ancount: int = 0,
               nscount: int = 0, arcount: int = 0) -> bytes:
    return struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)


def question(name: bytes, qtype: int = A, qclass: int = IN) -> bytes:
    return name + struct.pack("!HH", qtype, qclass)


def query_payload(txid: int, name: bytes, qtype: int = A, qclass: int = IN,
                  flags: int = 0x0100, qdcount: int = 1) -> bytes:
    return dns_header(txid, flags, qdcount) + question(name, qtype, qclass)


def rr(owner: bytes = b"\xc0\x0c", rtype: int = A, rclass: int = IN,
       ttl: int = 60, rdata: bytes = b"\xc0\x00\x02\x01",
       rdlen: int | None = None) -> bytes:
    if rdlen is None:
        rdlen = len(rdata)
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, rdlen) + rdata


def response_payload(txid: int, name: bytes, qtype: int = A,
                     answers: list[bytes] | None = None, qclass: int = IN,
                     flags: int = 0x8180, qdcount: int = 1,
                     ancount: int | None = None) -> bytes:
    answers = [] if answers is None else answers
    if ancount is None:
        ancount = len(answers)
    return (dns_header(txid, flags, qdcount, ancount) +
            question(name, qtype, qclass) + b"".join(answers))


def udp(payload: bytes, source: int, dest: int, length: int | None = None,
        checksum: int = 0) -> bytes:
    if length is None:
        length = 8 + len(payload)
    return struct.pack("!HHHH", source, dest, length, checksum) + payload


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return (b"\x02\x00\x00\x00\x00\x02" +
            b"\x02\x00\x00\x00\x00\x01" +
            struct.pack("!H", ethertype) + payload)


def ipv4(payload: bytes, protocol: int = 17, ihl: int = 5,
         version: int = 4, fragment: int = 0,
         total_length: int | None = None, options: bytes | None = None) -> bytes:
    if options is None:
        options = b"\x00" * max(0, ihl * 4 - 20)
    actual_header_len = 20 + len(options)
    if total_length is None:
        total_length = actual_header_len + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) | (ihl & 0x0F), 0, total_length & 0xFFFF,
        0x1234, fragment, 64, protocol, 0,
        ipaddress.IPv4Address("192.0.2.1").packed,
        ipaddress.IPv4Address("198.51.100.53").packed,
    )
    return header + options + payload


def ipv6(payload: bytes, next_header: int = 17, version: int = 6,
         payload_length: int | None = None) -> bytes:
    if payload_length is None:
        payload_length = len(payload)
    return struct.pack(
        "!IHBB16s16s", version << 28, payload_length & 0xFFFF,
        next_header, 64,
        ipaddress.IPv6Address("2001:db8::1").packed,
        ipaddress.IPv6Address("2001:db8::53").packed,
    ) + payload


def frame4(payload: bytes, direction: int, source: int | None = None,
           dest: int | None = None, **ip_kwargs: object) -> bytes:
    if source is None:
        source = 40000 if direction == QUERY else 53
    if dest is None:
        dest = 53 if direction == QUERY else 40000
    return ethernet(ipv4(udp(payload, source, dest), **ip_kwargs))


def frame6(payload: bytes, direction: int, source: int | None = None,
           dest: int | None = None, **ip_kwargs: object) -> bytes:
    if source is None:
        source = 40000 if direction == QUERY else 53
    if dest is None:
        dest = 53 if direction == QUERY else 40000
    return ethernet(ipv6(udp(payload, source, dest), **ip_kwargs), 0x86DD)


def count(**values: int) -> dict[str, int]:
    return values


class Matrix:
    def __init__(self, first_txid: int = 0x1000) -> None:
        self.cases: list[Case] = []
        self.next_txid = first_txid

    def txid(self) -> int:
        value = self.next_txid
        self.next_txid += 1
        return value

    def add(self, case: Case) -> None:
        if not 0 <= case.txid <= 0xFFFF:
            raise ValueError(f"bad transaction ID in {case.name}")
        self.cases.append(case)

    def pair(self, stem: str, name: str, qtype: int, answers: list[bytes],
             *, ipv6_transport: bool = False,
             response_counters: dict[str, int] | None = None) -> int:
        txid = self.txid()
        qname = wire_name(name)
        make_frame = frame6 if ipv6_transport else frame4
        family_counter = "PACKET_IPV6" if ipv6_transport else "PACKET_IPV4"
        self.add(Case(
            f"{stem}: query", QUERY, txid,
            make_frame(query_payload(txid, qname, qtype), QUERY),
            count(**{family_counter: 1, "QUERY_PACKET": 1,
                     "QUERY_STORED": 1}),
            True, name, qtype,
        ))
        expected = {
            family_counter: 1,
            "RESP_PACKET": 1,
            "RESP_ANSWER_SEEN": len(answers),
            "RESP_ADDR_PARSED": len(answers),
            "RESP_TOUCH": len(answers),
            "RESP_DELETE": 1,
            "TOUCH_CALLED": len(answers),
        }
        if response_counters:
            expected.update(response_counters)
        self.add(Case(
            f"{stem}: response", RESPONSE, txid,
            make_frame(response_payload(txid, qname, qtype, answers), RESPONSE),
            expected, False,
        ))
        return txid


def add_transport_cases(matrix: Matrix) -> None:
    txid = matrix.txid()
    matrix.add(Case("transport: non-IP EtherType", QUERY, txid,
                    ethernet(b"not ip", 0x88B5), {}, False))

    txid = matrix.txid()
    matrix.add(Case("transport: IPv4 non-UDP", QUERY, txid,
                    ethernet(ipv4(b"tcp", protocol=6)),
                    count(PACKET_IPV4=1, PACKET_NOT_UDP=1), False))

    txid = matrix.txid()
    matrix.add(Case("transport: IPv6 non-UDP", RESPONSE, txid,
                    ethernet(ipv6(b"tcp", next_header=6), 0x86DD),
                    count(PACKET_IPV6=1, PACKET_NOT_UDP=1), False))

    txid = matrix.txid()
    payload = query_payload(txid, wire_name("port.example"))
    matrix.add(Case("transport: query wrong destination port", QUERY, txid,
                    frame4(payload, QUERY, dest=5353),
                    count(PACKET_IPV4=1, PACKET_PORT_SKIP=1), False))

    txid = matrix.txid()
    payload = response_payload(txid, wire_name("port.example"), answers=[rr()])
    matrix.add(Case("transport: response wrong source port", RESPONSE, txid,
                    frame4(payload, RESPONSE, source=5353),
                    count(PACKET_IPV4=1, PACKET_PORT_SKIP=1), False))

    txid = matrix.txid()
    payload = query_payload(txid, wire_name("ihl.example"))
    matrix.add(Case("transport: IPv4 IHL below minimum", QUERY, txid,
                    frame4(payload, QUERY, ihl=4), count(PACKET_IPV4=1), False))

    txid = matrix.txid()
    matrix.add(Case("transport: truncated IPv4 header", QUERY, txid,
                    ethernet(b"\x45" + b"\x00" * 18),
                    {}, False, run_rc=-22, retval=0))

    txid = matrix.txid()
    matrix.add(Case("transport: truncated IPv6 header", RESPONSE, txid,
                    ethernet(b"\x60" + b"\x00" * 38, 0x86DD),
                    {}, False, run_rc=-22, retval=0))

    txid = matrix.txid()
    payload = query_payload(txid, wire_name("options.example"))
    matrix.add(Case("transport: IPv4 maximum IHL", QUERY, txid,
                    frame4(payload, QUERY, ihl=15),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, "options.example", A))
    matrix.add(Case("transport: IPv4 maximum IHL response", RESPONSE, txid,
                    frame4(response_payload(txid, wire_name("options.example"),
                                            answers=[rr(rdata=b"\xc0\x00\x02\x02")]),
                           RESPONSE, ihl=15),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=1,
                          RESP_ADDR_PARSED=1, RESP_TOUCH=1, RESP_DELETE=1,
                          TOUCH_CALLED=1), False))


def add_query_cases(matrix: Matrix) -> None:
    for suffix, payload, expected in (
        ("empty DNS payload", b"", count(QUERY_PACKET=1, QUERY_HDR_FAIL=1)),
        ("two-byte DNS payload", b"\x12\x34", count(QUERY_PACKET=1, QUERY_HDR_FAIL=1)),
        ("four-byte DNS payload", b"\x12\x34\x01\x00", count(QUERY_PACKET=1, QUERY_HDR_FAIL=1)),
    ):
        txid = matrix.txid()
        matrix.add(Case(f"query: {suffix}", QUERY, txid,
                        frame4(payload, QUERY),
                        {"PACKET_IPV4": 1, **expected}, False))

    txid = matrix.txid()
    matrix.add(Case("query: QR bit set", QUERY, txid,
                    frame4(query_payload(txid, wire_name("qr.example"), flags=0x8100), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_IS_RESPONSE=1), False))

    for qdcount in (0, 2):
        txid = matrix.txid()
        matrix.add(Case(f"query: qdcount {qdcount}", QUERY, txid,
                        frame4(query_payload(txid, wire_name("qd.example"),
                                             qdcount=qdcount), QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1,
                              QUERY_QDCOUNT_BAD=1), False))

    malformed_names = (
        ("header only", b""),
        ("reserved label prefix 01", b"\x40"),
        ("reserved label prefix 10", b"\x80"),
        ("compression in query", b"\xc0\x0c"),
        ("label length 64", b"\x40" + b"a" * 64 + b"\x00"),
        ("truncated label", b"\x05abc"),
        ("missing terminator", b"\x03abc"),
    )
    for suffix, raw_name in malformed_names:
        txid = matrix.txid()
        payload = dns_header(txid, 0x0100, 1) + raw_name
        matrix.add(Case(f"query name: {suffix}", QUERY, txid,
                        frame4(payload, QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1,
                              QUERY_NAME_FAIL=1), False))

    txid = matrix.txid()
    payload = dns_header(txid, 0x0100, 1) + b"\x00" + struct.pack("!HH", A, IN)
    matrix.add(Case("query name: root", QUERY, txid, frame4(payload, QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_EMPTY_NAME=1), False))

    for suffix, tail in (("missing qtype", b""), ("missing qclass", struct.pack("!H", A))):
        txid = matrix.txid()
        payload = dns_header(txid, 0x0100, 1) + wire_name("short.example") + tail
        matrix.add(Case(f"query: {suffix}", QUERY, txid,
                        frame4(payload, QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1,
                              QUERY_QTYPE_READ_FAIL=1), False))

    txid = matrix.txid()
    matrix.add(Case("query: unsupported TXT qtype", QUERY, txid,
                    frame4(query_payload(txid, wire_name("txt.example"), 16), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1,
                          QUERY_QTYPE_UNSUPPORTED=1), False))


def add_response_state_cases(matrix: Matrix) -> None:
    qname = wire_name("state.example")

    txid = matrix.txid()
    matrix.add(Case("response: short header", RESPONSE, txid,
                    frame4(b"\x12\x34\x81\x80\x00\x01", RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_HDR_FAIL=1), False))

    txid = matrix.txid()
    matrix.add(Case("response: unsolicited", RESPONSE, txid,
                    frame4(response_payload(txid, qname, answers=[rr()]), RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_REQ_MISS=1), False))

    # Early header-state rejects retain the request; the final valid response
    # consumes it.  This makes retention visible rather than inferred.
    for suffix, kwargs, branch in (
        ("QR clear", {"flags": 0x0100}, "RESP_NOT_RESPONSE"),
        ("qdcount zero", {"qdcount": 0}, "RESP_QDCOUNT_BAD"),
        ("no answers", {"ancount": 0}, "RESP_NO_ANSWER"),
    ):
        txid = matrix.txid()
        name = f"retain-{txid:x}.example"
        raw_name = wire_name(name)
        matrix.add(Case(f"response state {suffix}: query", QUERY, txid,
                        frame4(query_payload(txid, raw_name), QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                        True, name, A))
        payload = response_payload(txid, raw_name, answers=[rr()], **kwargs)
        matrix.add(Case(f"response state: {suffix}", RESPONSE, txid,
                        frame4(payload, RESPONSE),
                        count(PACKET_IPV4=1, RESP_PACKET=1, **{branch: 1}),
                        True, name, A))
        matrix.add(Case(f"response state {suffix}: cleanup", RESPONSE, txid,
                        frame4(response_payload(txid, raw_name, answers=[rr(rdata=b"\xc0\x00\x02\x40")]), RESPONSE),
                        count(PACKET_IPV4=1, RESP_PACKET=1,
                              RESP_ANSWER_SEEN=1, RESP_ADDR_PARSED=1,
                              RESP_TOUCH=1, RESP_DELETE=1, TOUCH_CALLED=1), False))

    destructive = (
        ("malformed question name", b"\x40", "RESP_QNAME_SKIP_FAIL"),
        ("truncated question type", wire_name("state.example") + b"\x00", "RESP_QTYPE_READ_FAIL"),
    )
    for suffix, question_bytes, branch in destructive:
        txid = matrix.txid()
        matrix.add(Case(f"response {suffix}: query", QUERY, txid,
                        frame4(query_payload(txid, qname), QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                        True, "state.example", A))
        payload = dns_header(txid, 0x8180, 1, 1) + question_bytes
        matrix.add(Case(f"response: {suffix}", RESPONSE, txid,
                        frame4(payload, RESPONSE),
                        count(PACKET_IPV4=1, RESP_PACKET=1, **{branch: 1}), False))

    txid = matrix.txid()
    matrix.add(Case("response qtype mismatch: query", QUERY, txid,
                    frame4(query_payload(txid, qname, A), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, "state.example", A))
    matrix.add(Case("response: qtype mismatch", RESPONSE, txid,
                    frame4(response_payload(txid, qname, AAAA,
                                            [rr(rtype=AAAA, rdata=b"\x00" * 16)]), RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1,
                          RESP_QTYPE_MISMATCH=1), False))


def add_rr_cases(matrix: Matrix) -> None:
    scenarios: list[tuple[str, bytes, dict[str, int]]] = [
        ("malformed owner", b"\x40", count(RESP_ANSWER_SEEN=1,
                                             RESP_ANSWER_SKIP_FAIL=1,
                                             RESP_DELETE=1)),
        ("truncated fixed fields", b"\xc0\x0c\x00\x01", count(RESP_ANSWER_SEEN=1,
                                                               RESP_RR_READ_FAIL=1,
                                                               RESP_DELETE=1)),
        ("RDATA logical bounds", rr(rdlen=0xFFFF, rdata=b""),
         count(RESP_ANSWER_SEEN=1, RESP_RDATA_BOUNDS_FAIL=1,
               RESP_DELETE=1)),
        ("unsupported TXT", rr(rtype=16, rdata=b"data"),
         count(RESP_ANSWER_SEEN=1, RESP_ADDR_UNSUPPORTED=1,
               RESP_DELETE=1)),
        ("A wrong RDLENGTH", rr(rtype=A, rdata=b"\xc0\x00\x02", rdlen=3),
         count(RESP_ANSWER_SEEN=1, RESP_ADDR_UNSUPPORTED=1,
               RESP_DELETE=1)),
        ("AAAA wrong RDLENGTH", rr(rtype=AAAA, rdata=b"\x00" * 15, rdlen=15),
         count(RESP_ANSWER_SEEN=1, RESP_ADDR_UNSUPPORTED=1,
               RESP_DELETE=1)),
        ("truncated A RDATA", rr(rtype=A, rdata=b"\xc0\x00", rdlen=4),
         count(RESP_ANSWER_SEEN=1, RESP_DELETE=1)),
    ]
    for suffix, answer, expected in scenarios:
        txid = matrix.txid()
        name = f"rr-{txid:x}.example"
        qname = wire_name(name)
        matrix.add(Case(f"RR {suffix}: query", QUERY, txid,
                        frame4(query_payload(txid, qname), QUERY),
                        count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                        True, name, A))
        payload = response_payload(txid, qname, answers=[answer])
        matrix.add(Case(f"RR: {suffix}", RESPONSE, txid,
                        frame4(payload, RESPONSE),
                        {"PACKET_IPV4": 1, "RESP_PACKET": 1, **expected}, False))

    # Both compressed and full owner names are supported by the answer walker.
    full_owner = wire_name("owner.example")
    matrix.pair("RR full owner", "owner.example", A,
                [rr(owner=full_owner, rdata=b"\xc0\x00\x02\x50")])
    partial_owner = b"\x03www\xc0\x0c"
    matrix.pair("RR partial compression", "partial.example", A,
                [rr(owner=partial_owner, rdata=b"\xc0\x00\x02\x51")])

    # Unsupported records are skipped while later supported records are used.
    txid = matrix.txid()
    name = "mixed.example"
    qname = wire_name(name)
    answers = [rr(rtype=16, rdata=b"txt"), rr(rdata=b"\xcb\x00\x71\x4a")]
    matrix.add(Case("RR mixed types: query", QUERY, txid,
                    frame4(query_payload(txid, qname), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, name, A))
    matrix.add(Case("RR mixed types: response", RESPONSE, txid,
                    frame4(response_payload(txid, qname, answers=answers), RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=2,
                          RESP_ADDR_UNSUPPORTED=1, RESP_ADDR_PARSED=1,
                          RESP_TOUCH=1, RESP_DELETE=1, TOUCH_CALLED=1), False))

    # The loop is intentionally capped at 75 answers.
    fillers = [rr(rtype=16, rdata=b"x") for _ in range(74)]
    matrix.pair("RR supported answer at slot 75", "slot75.example", A,
                fillers + [rr(rdata=b"\xcb\x00\x71\x4b")],
                response_counters={"RESP_ADDR_UNSUPPORTED": 74,
                                   "RESP_ADDR_PARSED": 1,
                                   "RESP_TOUCH": 1,
                                   "TOUCH_CALLED": 1})

    txid = matrix.txid()
    name = "slot76.example"
    qname = wire_name(name)
    answers = [rr(rtype=16, rdata=b"x") for _ in range(75)]
    answers.append(rr(rdata=b"\xcb\x00\x71\x4c"))
    matrix.add(Case("RR answer beyond slot 75: query", QUERY, txid,
                    frame4(query_payload(txid, qname), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, name, A))
    matrix.add(Case("RR answer beyond slot 75: response", RESPONSE, txid,
                    frame4(response_payload(txid, qname, answers=answers), RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=75,
                          RESP_ADDR_UNSUPPORTED=75, RESP_DELETE=1), False))

    # A valid first answer remains observable when a later answer is malformed.
    txid = matrix.txid()
    name = "partial-response.example"
    qname = wire_name(name)
    payload = response_payload(txid, qname,
                               answers=[rr(rdata=b"\xc0\x00\x02\x52")],
                               ancount=2)
    matrix.add(Case("RR partial response: query", QUERY, txid,
                    frame4(query_payload(txid, qname), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, name, A))
    matrix.add(Case("RR partial response", RESPONSE, txid,
                    frame4(payload, RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=2,
                          RESP_ANSWER_SKIP_FAIL=1, RESP_ADDR_PARSED=1,
                          RESP_TOUCH=1, RESP_DELETE=1, TOUCH_CALLED=1), False))

    # Trailing records above ANCOUNT are ignored.
    txid = matrix.txid()
    name = "ancount-limit.example"
    qname = wire_name(name)
    encoded = (dns_header(txid, 0x8180, 1, 1) + question(qname) +
               rr(rdata=b"\xc0\x00\x02\x53") +
               rr(rdata=b"\xc0\x00\x02\x54"))
    matrix.add(Case("RR ANCOUNT limit: query", QUERY, txid,
                    frame4(query_payload(txid, qname), QUERY),
                    count(PACKET_IPV4=1, QUERY_PACKET=1, QUERY_STORED=1),
                    True, name, A))
    matrix.add(Case("RR ANCOUNT limit", RESPONSE, txid, frame4(encoded, RESPONSE),
                    count(PACKET_IPV4=1, RESP_PACKET=1, RESP_ANSWER_SEEN=1,
                          RESP_ADDR_PARSED=1, RESP_TOUCH=1,
                          RESP_DELETE=1, TOUCH_CALLED=1), False))


def build_deterministic_matrix() -> Matrix:
    matrix = Matrix()
    add_transport_cases(matrix)
    add_query_cases(matrix)
    add_response_state_cases(matrix)
    add_rr_cases(matrix)

    matrix.pair("valid IPv4 A", "basic.example", A,
                [rr(rdata=b"\xc0\x00\x02\x0a")],
                response_counters={"ALLOC_ATTEMPT": 1, "ALLOC_OK": 1,
                                   "CAS_OK": 1})
    matrix.pair("valid IPv6 transport and AAAA", "v6.example", AAAA,
                [rr(rtype=AAAA,
                    rdata=ipaddress.IPv6Address("2001:db8::10").packed)],
                ipv6_transport=True)

    long_name = ".".join(["a"] * 127)
    matrix.pair("127-label maximum wire name", long_name, A,
                [rr(rdata=b"\xc0\x00\x02\x0b")])

    # Multiple answers for one address exercise lookup and seen_count updates.
    matrix.pair("duplicate address answer", "duplicate.example", A,
                [rr(rdata=b"\xc0\x00\x02\x14"),
                 rr(rdata=b"\xc0\x00\x02\x14")],
                response_counters={"ALLOC_ATTEMPT": 1, "ALLOC_OK": 1,
                                   "CAS_OK": 1, "TOUCH_HIT": 1})

    # One address stores four names and evicts the oldest on the fifth.
    for index in range(1, 6):
        matrix.pair(f"name slot {index}", f"name{index}.example", A,
                    [rr(rdata=b"\xc0\x00\x02\x15")])

    matrix.pair("one name, two addresses", "multi-address.example", A,
                [rr(rdata=b"\xc0\x00\x02\x1e"),
                 rr(rdata=b"\xc0\x00\x02\x1f")])
    return matrix


def encode_batch(cases: list[Case]) -> bytes:
    output = bytearray(struct.pack("<IHHI", BATCH_MAGIC, BATCH_VERSION, 0,
                                   len(cases)))
    for case in cases:
        if len(case.frame) > 0xFFFF:
            raise ValueError(f"frame too large in {case.name}: {len(case.frame)}")
        output.extend(struct.pack("<HBBHH", len(case.frame), case.direction,
                                  0, case.txid, 0))
        output.extend(case.frame)
    return bytes(output)


def invoke_runner(runner: Path, cases: list[Case], artifact: Path | None = None) -> list[dict]:
    batch = encode_batch(cases)
    if artifact is not None:
        artifact.write_bytes(batch)
    process = subprocess.run([str(runner)], input=batch, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, check=False)
    if process.returncode:
        raise RuntimeError(
            f"runner exited {process.returncode}: " +
            process.stderr.decode("utf-8", "replace").strip())
    try:
        results = [json.loads(line) for line in process.stdout.splitlines()]
    except json.JSONDecodeError as error:
        raise RuntimeError(f"invalid runner JSON: {error}") from error
    if len(results) != len(cases):
        raise RuntimeError(f"runner returned {len(results)} results for {len(cases)} cases")
    return results


def assert_results(cases: list[Case], results: list[dict]) -> set[str]:
    hit: set[str] = set()
    failures: list[str] = []
    for index, (case, result) in enumerate(zip(cases, results)):
        prefix = f"case {index} ({case.name})"
        if result.get("index") != index:
            failures.append(f"{prefix}: result index is {result.get('index')!r}")
        if (result.get("rc") != case.run_rc or
                result.get("retval") != case.retval):
            failures.append(
                f"{prefix}: BPF_PROG_TEST_RUN rc={result.get('rc')} "
                f"retval={result.get('retval')}, expected rc={case.run_rc} "
                f"retval={case.retval}")
        delta = result.get("counter_delta")
        if not isinstance(delta, list) or len(delta) != len(COUNTERS):
            failures.append(f"{prefix}: malformed counter delta")
            continue
        hit.update(COUNTERS[i] for i, value in enumerate(delta) if value)
        for name, expected in case.counters.items():
            actual = delta[COUNTER[name]]
            if actual != expected:
                failures.append(f"{prefix}: {name}={actual}, expected {expected}")
        if case.request is not None and result.get("request") is not case.request:
            failures.append(
                f"{prefix}: request={result.get('request')!r}, expected {case.request}")
        if case.request_name is not None:
            actual_name = bytes.fromhex(result.get("request_name_hex", "")).decode(
                "ascii", "backslashreplace")
            if actual_name != case.request_name:
                failures.append(
                    f"{prefix}: request name {actual_name!r}, expected {case.request_name!r}")
        if case.request_qtype is not None and result.get("request_qtype") != case.request_qtype:
            failures.append(
                f"{prefix}: qtype={result.get('request_qtype')}, expected {case.request_qtype}")
    if failures:
        raise AssertionError("\n".join(failures))
    return hit


def export_dns(shirudo: Path, upatch: str, output: Path) -> dict:
    process = subprocess.run(
        [str(shirudo), "upatch", "map", upatch, "dns_arena",
         f"--json={output}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, text=True)
    if process.returncode:
        raise RuntimeError(
            f"DNS export exited {process.returncode}: {process.stderr.strip()}")
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    if len(records) != 1 or records[0].get("map") != "dns_arena":
        raise AssertionError(f"unexpected DNS export: {records!r}")
    return records[0]


def names_by_address(export: dict) -> dict[str, dict[str, int]]:
    output: dict[str, dict[str, int]] = {}
    for record in export.get("records", []):
        output.setdefault(record["address"], {}).update(
            {item["name"]: int(item["seen_count"]) for item in record["names"]})
    return output


def assert_export(export: dict) -> None:
    addresses = names_by_address(export)
    required = {
        "192.0.2.10": {"basic.example": 1},
        "2001:0db8:0000:0000:0000:0000:0000:0010": {"v6.example": 1},
        "192.0.2.11": {".".join(["a"] * 127): 1},
        "192.0.2.20": {"duplicate.example": 2},
        "192.0.2.21": {f"name{i}.example": 1 for i in range(2, 6)},
        "192.0.2.30": {"multi-address.example": 1},
        "192.0.2.31": {"multi-address.example": 1},
        "203.0.113.75": {"slot75.example": 1},
    }
    failures: list[str] = []
    for address, expected_names in required.items():
        actual_names = addresses.get(address)
        if actual_names is None:
            failures.append(f"missing exported address {address}")
            continue
        for name, seen_count in expected_names.items():
            if actual_names.get(name) != seen_count:
                failures.append(
                    f"{address} name {name!r}: seen_count={actual_names.get(name)}, "
                    f"expected {seen_count}")
    if "name1.example" in addresses.get("192.0.2.21", {}):
        failures.append("oldest fifth-name slot was not evicted")
    if "203.0.113.76" in addresses:
        failures.append("answer 76 was parsed despite the 75-answer cap")
    if failures:
        raise AssertionError("\n".join(failures))


def build_known_gap_matrix() -> tuple[list[Case], list[tuple[str, Callable[[dict], bool]]]]:
    matrix = Matrix(0x7000)
    probes: list[tuple[str, Callable[[dict], bool]]] = []

    def add_query_probe(label: str, frame_builder: Callable[[int, bytes], bytes],
                        qclass: int = IN, name: str | None = None) -> None:
        txid = matrix.txid()
        text_name = name or f"gap-{txid:x}.example"
        raw_name = wire_name(text_name)
        case_index = len(matrix.cases)
        payload = query_payload(txid, raw_name, qclass=qclass)
        matrix.add(Case(label, QUERY, txid, frame_builder(txid, payload), request=None))
        probes.append((label, lambda result: bool(result["request"])))
        matrix.add(Case(label + ": cleanup", RESPONSE, txid,
                        frame4(response_payload(txid, raw_name, answers=[rr()]), RESPONSE),
                        request=None))
        assert case_index == len(matrix.cases) - 2

    add_query_probe("fragmented IPv4 query is accepted",
                    lambda _txid, payload: frame4(payload, QUERY, fragment=0x2000))
    add_query_probe("non-IN question class is accepted",
                    lambda _txid, payload: frame4(payload, QUERY), qclass=3)

    txid = matrix.txid()
    original = wire_name("original.example")
    other = wire_name("different.example")
    matrix.add(Case("response qname mismatch: query", QUERY, txid,
                    frame4(query_payload(txid, original), QUERY), request=None))
    response_index = len(matrix.cases)
    matrix.add(Case("response qname mismatch is accepted", RESPONSE, txid,
                    frame4(response_payload(txid, other, answers=[rr()]), RESPONSE),
                    request=None))
    probes.append(("response qname is not matched to query",
                   lambda result: (not result["request"] and
                                   result["counter_delta"][COUNTER["RESP_TOUCH"]] == 1)))

    txid = matrix.txid()
    raw_name = wire_name("pointer.example")
    matrix.add(Case("unchecked pointer target: query", QUERY, txid,
                    frame4(query_payload(txid, raw_name), QUERY), request=None))
    pointer_index = len(matrix.cases)
    matrix.add(Case("unchecked compression pointer target", RESPONSE, txid,
                    frame4(response_payload(txid, raw_name,
                                            answers=[rr(owner=b"\xff\xff")]), RESPONSE),
                    request=None))
    probes.append(("answer compression pointer target is not validated",
                   lambda result: result["counter_delta"][COUNTER["RESP_TOUCH"]] == 1))

    txid = matrix.txid()
    raw_name = wire_name("flags.example")
    matrix.add(Case("response flags: query", QUERY, txid,
                    frame4(query_payload(txid, raw_name), QUERY), request=None))
    flags_index = len(matrix.cases)
    matrix.add(Case("response opcode/rcode/TC flags", RESPONSE, txid,
                    frame4(response_payload(txid, raw_name, answers=[rr()],
                                            flags=0x8B83), RESPONSE), request=None))
    probes.append(("response opcode, rcode, and TC are not filtered",
                   lambda result: result["counter_delta"][COUNTER["RESP_TOUCH"]] == 1))

    txid = matrix.txid()
    first = wire_name("collision-first.example")
    second = wire_name("collision-second.example")
    matrix.add(Case("transaction collision first query", QUERY, txid,
                    frame4(query_payload(txid, first), QUERY), request=None))
    collision_index = len(matrix.cases)
    matrix.add(Case("transaction collision overwrites query", QUERY, txid,
                    frame4(query_payload(txid, second), QUERY), request=None))
    probes.append(("request key is transaction ID only",
                   lambda result: bytes.fromhex(result["request_name_hex"]) ==
                   b"collision-second.example"))
    matrix.add(Case("transaction collision: cleanup", RESPONSE, txid,
                    frame4(response_payload(txid, second, answers=[rr()]), RESPONSE),
                    request=None))

    txid = matrix.txid()
    raw_name = wire_name("length.example")
    dns = query_payload(txid, raw_name)
    malformed_udp = udp(dns, 40000, 53, length=8)
    length_index = len(matrix.cases)
    matrix.add(Case("UDP length shorter than DNS payload", QUERY, txid,
                    ethernet(ipv4(malformed_udp)), request=None))
    probes.append(("IPv4 and UDP declared lengths are not enforced",
                   lambda result: bool(result["request"])))
    matrix.add(Case("UDP length: cleanup", RESPONSE, txid,
                    frame4(response_payload(txid, raw_name, answers=[rr()]), RESPONSE),
                    request=None))

    txid = matrix.txid()
    raw_name = wire_name("oversize.example")
    oversize_index = len(matrix.cases)
    matrix.add(Case("packet larger than 1232-byte parsing budget", QUERY, txid,
                    frame4(query_payload(txid, raw_name) + b"x" * 1300, QUERY),
                    request=None))
    probes.append(("overall UDP packet size is not capped at 1232 bytes",
                   lambda result: bool(result["request"])))
    matrix.add(Case("oversize packet: cleanup", RESPONSE, txid,
                    frame4(response_payload(txid, raw_name, answers=[rr()]), RESPONSE),
                    request=None))

    # Keep the probe/result association explicit despite cleanup actions.
    probe_indices = [0, 2, response_index, pointer_index, flags_index,
                     collision_index, length_index, oversize_index]
    return matrix.cases, [(label, (lambda pred, index: lambda results: pred(results[index]))(predicate, index))
                          for (label, predicate), index in zip(probes, probe_indices)]


def validate_matrix(cases: list[Case]) -> None:
    if not cases:
        raise AssertionError("empty DNS test matrix")
    names = [case.name for case in cases]
    if len(names) != len(set(names)):
        raise AssertionError("duplicate DNS matrix case names")
    batch = encode_batch(cases)
    if struct.unpack_from("<IHHI", batch) != (BATCH_MAGIC, BATCH_VERSION, 0, len(cases)):
        raise AssertionError("batch header self-test failed")
    offset = struct.calcsize("<IHHI")
    for expected, case in enumerate(cases):
        frame_len, direction, flags, txid, reserved = struct.unpack_from("<HBBHH", batch, offset)
        offset += struct.calcsize("<HBBHH")
        if (frame_len, direction, flags, txid, reserved) != (
                len(case.frame), case.direction, 0, case.txid, 0):
            raise AssertionError(f"batch record self-test failed at {expected}")
        if batch[offset:offset + frame_len] != case.frame:
            raise AssertionError(f"batch frame self-test failed at {expected}")
        offset += frame_len
    if offset != len(batch):
        raise AssertionError("batch has trailing bytes")


def run_deterministic(args: argparse.Namespace, work: Path) -> None:
    matrix = build_deterministic_matrix()
    validate_matrix(matrix.cases)
    results = invoke_runner(args.runner, matrix.cases, work / "dns-matrix.batch")
    hit = assert_results(matrix.cases, results)
    (work / "dns-matrix-results.ndjson").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
        encoding="utf-8")

    required = set(COUNTERS) - NON_PACKET_COUNTERS
    missing = sorted(required - hit)
    if missing:
        raise AssertionError("packet-controlled debug counters not covered: " +
                             ", ".join(missing))

    first_export = export_dns(args.shirudo, args.upatch,
                              work / "dns-matrix-export.ndjson")
    assert_export(first_export)
    second_export = export_dns(args.shirudo, args.upatch,
                               work / "dns-matrix-export-empty.ndjson")
    if second_export.get("records"):
        raise AssertionError("DNS serializer did not clear pending records")

    print(f"PASS deterministic: {len(matrix.cases)} exact packets, "
          f"{len(hit)} debug branches, serializer output and clear-on-export")

    if args.known_gaps:
        known_cases, probes = build_known_gap_matrix()
        known_results = invoke_runner(args.runner, known_cases,
                                      work / "dns-known-gaps.batch")
        # Known gaps do not carry semantic assertions, but syscall execution
        # and the runner protocol remain gating.
        assert_results(known_cases, known_results)
        report: list[str] = []
        for label, predicate in probes:
            status = "XFAIL known-gap" if predicate(known_results) else "RESOLVED"
            report.append(f"{status}: {label}")
        report.extend([
            "LIMITATION: IPv6 extension headers are not walked",
            "LIMITATION: response question class is read but not compared",
            "LIMITATION: answer type is not constrained by the requested type",
            "LIMITATION: IP/UDP checksums are not validated",
        ])
        text = "\n".join(report) + "\n"
        (work / "dns-known-gaps.log").write_text(text, encoding="utf-8")
        print(text, end="")


def mutate_packet(rng: random.Random, corpus: list[bytes]) -> bytes:
    packet = bytearray(rng.choice(corpus))
    operation = rng.randrange(6)
    if operation == 0 and packet:
        del packet[rng.randrange(len(packet)):]
    elif operation == 1 and packet:
        for _ in range(rng.randint(1, min(16, len(packet)))):
            index = rng.randrange(len(packet))
            packet[index] ^= 1 << rng.randrange(8)
    elif operation == 2:
        at = rng.randrange(len(packet) + 1)
        packet[at:at] = rng.randbytes(rng.randint(1, 32))
    elif operation == 3 and len(packet) > 14:
        start = rng.randrange(14, len(packet))
        end = min(len(packet), start + rng.randint(1, 32))
        del packet[start:end]
    elif operation == 4:
        packet.extend(rng.randbytes(rng.randint(0, 512)))
    elif len(packet) >= 14:
        packet[12:14] = rng.choice((b"\x08\x00", b"\x86\xdd", b"\x88\xb5"))
    return bytes(packet[:65535])


def assert_fuzz_results(cases: list[Case], results: list[dict]) -> None:
    failures: list[str] = []
    for index, (case, result) in enumerate(zip(cases, results)):
        if result.get("index") != index:
            failures.append(
                f"case {index}: result index is {result.get('index')!r}")
        outcome = (result.get("rc"), result.get("retval"))
        # The skb test harness rejects frames that no longer satisfy its
        # minimum L2/L3 shape before invoking BPF.  That is a valid fuzz
        # outcome; anything besides success or EINVAL is not.
        if outcome not in ((0, 1), (-22, 0)):
            failures.append(
                f"case {index} ({case.name}): unexpected rc/retval {outcome}")
        delta = result.get("counter_delta")
        if not isinstance(delta, list) or len(delta) != len(COUNTERS):
            failures.append(f"case {index} ({case.name}): malformed counter delta")
        if len(failures) >= 20:
            break
    if failures:
        raise AssertionError("\n".join(failures))


def run_fuzz(args: argparse.Namespace, work: Path) -> None:
    rng = random.Random(args.seed)
    deterministic = build_deterministic_matrix().cases
    corpus = [case.frame for case in deterministic]
    cases: list[Case] = []
    for index in range(args.cases):
        direction = rng.randrange(2)
        cases.append(Case(f"fuzz-{index}", direction, rng.randrange(0x10000),
                          mutate_packet(rng, corpus), request=None))
    validate_matrix(cases)
    results = invoke_runner(args.runner, cases, work / "dns-fuzz.batch")
    assert_fuzz_results(cases, results)
    (work / "dns-fuzz-results.ndjson").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
        encoding="utf-8")
    print(f"PASS fuzz: seed={args.seed:#x}, cases={args.cases}")


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", type=Path, default=Path("helper/test-dns-prog-run"))
    parser.add_argument("--shirudo", type=Path, default=Path("/usr/local/bin/shirudo"))
    parser.add_argument("--upatch", default="linux-observability")
    parser.add_argument("--work", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--known-gaps", action="store_true")
    parser.add_argument("--fuzz", action="store_true")
    parser.add_argument("--seed", type=parse_int, default=0x53484952)
    parser.add_argument("--cases", type=int, default=5000)
    args = parser.parse_args()

    if args.cases < 1 or args.cases > 100000:
        parser.error("--cases must be between 1 and 100000")
    args.work.mkdir(parents=True, exist_ok=True)
    matrix = build_deterministic_matrix()
    validate_matrix(matrix.cases)
    if args.self_test:
        known_cases, _ = build_known_gap_matrix()
        validate_matrix(known_cases)
        print(f"PASS matrix self-test: {len(matrix.cases)} deterministic packets, "
              f"{len(known_cases)} known-gap packets")
    if args.deterministic:
        run_deterministic(args, args.work)
    if args.fuzz:
        run_fuzz(args, args.work)
    if not (args.self_test or args.deterministic or args.fuzz):
        parser.error("select --self-test, --deterministic, or --fuzz")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
