"""Normalise scapy packets into a flat record the detectors can read cheaply."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

# TCP flag bit -> letter, in the order tcpdump prints them
_TCP_FLAGS = [
    (0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
    (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C"),
]


def decode_flags(value: int) -> str:
    return "".join(letter for bit, letter in _TCP_FLAGS if value & bit)


@dataclass(slots=True)
class PacketRecord:
    ts: float
    proto: str = "OTHER"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    tcp_flags: str = ""
    length: int = 0
    payload: bytes = b""
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    arp_op: Optional[int] = None
    arp_psrc: Optional[str] = None
    arp_hwsrc: Optional[str] = None
    ttl: Optional[int] = None

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)


def parse(pkt) -> Optional[PacketRecord]:
    """Build a PacketRecord from a scapy packet. Returns None for frames we ignore."""
    try:
        ts = float(getattr(pkt, "time", 0.0)) or time.time()
        rec = PacketRecord(ts=ts, length=len(pkt))

        if Ether in pkt:
            rec.src_mac = pkt[Ether].src
            rec.dst_mac = pkt[Ether].dst

        if ARP in pkt:
            arp = pkt[ARP]
            rec.proto = "ARP"
            rec.arp_op = int(arp.op)
            rec.arp_psrc = arp.psrc
            rec.arp_hwsrc = arp.hwsrc
            rec.src_ip = arp.psrc
            rec.dst_ip = arp.pdst
            return rec

        if IP in pkt:
            ip = pkt[IP]
            rec.src_ip = ip.src
            rec.dst_ip = ip.dst
            rec.ttl = int(ip.ttl)
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            rec.src_ip = ip6.src
            rec.dst_ip = ip6.dst
            rec.ttl = int(ip6.hlim)
        else:
            return rec if rec.src_mac else None

        if TCP in pkt:
            tcp = pkt[TCP]
            rec.proto = "TCP"
            rec.src_port = int(tcp.sport)
            rec.dst_port = int(tcp.dport)
            rec.tcp_flags = decode_flags(int(tcp.flags))
            rec.payload = bytes(tcp.payload)[:2048]
        elif UDP in pkt:
            udp = pkt[UDP]
            rec.proto = "UDP"
            rec.src_port = int(udp.sport)
            rec.dst_port = int(udp.dport)
            rec.payload = bytes(udp.payload)[:2048]
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            rec.proto = "ICMP"
            rec.icmp_type = int(icmp.type)
            rec.icmp_code = int(icmp.code)
            rec.payload = bytes(icmp.payload)[:2048]
        else:
            rec.proto = "IP"
        return rec
    except Exception:
        return None
