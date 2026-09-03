"""Detection logic: stateful heuristics + payload signatures."""
from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Any, Iterable, Optional

from .alerts import Alert
from .packet import PacketRecord


class SlidingWindow:
    """Timestamped events, trimmed to a fixed time horizon."""

    __slots__ = ("window", "events")

    def __init__(self, window: float) -> None:
        self.window = window
        self.events: dict[Any, deque] = defaultdict(deque)

    def add(self, key: Any, ts: float, value: Any = None) -> deque:
        dq = self.events[key]
        dq.append((ts, value))
        horizon = ts - self.window
        while dq and dq[0][0] < horizon:
            dq.popleft()
        return dq

    def values(self, key: Any) -> list:
        return [v for _, v in self.events[key]]

    def gc(self, now: float) -> None:
        """Drop keys whose events have all aged out, keeping memory bounded."""
        horizon = now - self.window
        for key in list(self.events):
            dq = self.events[key]
            while dq and dq[0][0] < horizon:
                dq.popleft()
            if not dq:
                del self.events[key]


class Detector:
    """Base class. Subclasses implement inspect(); cooldown suppresses alert floods."""

    sid: int = 0
    name: str = "base"
    severity: str = "low"
    category: str = "misc"
    cooldown: float = 20.0
    mitre: str = ""

    def __init__(self, **opts: Any) -> None:
        self.opts = opts
        self.enabled = opts.get("enabled", True)
        self._last_fired: dict[Any, float] = {}

    def _ready(self, key: Any, ts: float) -> bool:
        """True if this key has not alerted inside the cooldown period."""
        last = self._last_fired.get(key)
        if last is not None and ts - last < self.cooldown:
            return False
        self._last_fired[key] = ts
        return True

    def alert(self, rec: PacketRecord, detail: str, **evidence: Any) -> Alert:
        return Alert(
            sid=self.sid, name=self.name, severity=self.severity,
            category=self.category, src_ip=rec.src_ip, dst_ip=rec.dst_ip,
            src_port=rec.src_port, dst_port=rec.dst_port, proto=rec.proto,
            detail=detail, evidence=evidence, mitre=self.mitre,
        )

    def inspect(self, rec: PacketRecord) -> Iterable[Alert]:
        return ()

    def gc(self, now: float) -> None:
        pass


class PortScanDetector(Detector):
    """Many distinct destination ports on one host from one source: nmap -sS/-sT."""

    sid, name = 1000001, "TCP Port Scan"
    severity, category = "high", "recon"
    mitre = "T1046"

    def __init__(self, threshold: int = 15, window: float = 10.0, **opts: Any) -> None:
        super().__init__(**opts)
        self.threshold = threshold
        self.win = SlidingWindow(window)

    def inspect(self, rec: PacketRecord):
        if rec.proto != "TCP" or "S" not in rec.tcp_flags or "A" in rec.tcp_flags:
            return ()
        key = (rec.src_ip, rec.dst_ip)
        self.win.add(key, rec.ts, rec.dst_port)
        ports = set(self.win.values(key))
        if len(ports) >= self.threshold and self._ready(key, rec.ts):
            lo, hi = min(ports), max(ports)
            return (self.alert(
                rec,
                f"{len(ports)} distinct ports in {self.win.window:.0f}s "
                f"(range {lo}-{hi})",
                distinct_ports=len(ports),
                sample_ports=sorted(ports)[:25],
                window_seconds=self.win.window,
            ),)
        return ()

    def gc(self, now: float) -> None:
        self.win.gc(now)


class StealthScanDetector(Detector):
    """Illegal or evasive TCP flag combinations: NULL, FIN, XMAS, Maimon scans."""

    sid, name = 1000002, "Stealth Scan (anomalous TCP flags)"
    severity, category = "high", "recon"
    mitre = "T1046"
    cooldown = 10.0

    VARIANTS = {
        "": "NULL scan (no flags set)",
        "F": "FIN scan",
        "FPU": "XMAS scan (FIN+PSH+URG)",
        "FA": "Maimon scan (FIN+ACK)",
        "SF": "SYN+FIN (illegal combination)",
        "SR": "SYN+RST (illegal combination)",
        "FPUS": "full XMAS tree",
    }

    def inspect(self, rec: PacketRecord):
        if rec.proto != "TCP":
            return ()
        flags = "".join(sorted(rec.tcp_flags))
        for combo, label in self.VARIANTS.items():
            if "".join(sorted(combo)) == flags:
                key = (rec.src_ip, rec.dst_ip, flags)
                if self._ready(key, rec.ts):
                    return (self.alert(
                        rec, f"{label} against port {rec.dst_port}",
                        flags=rec.tcp_flags or "none", variant=label,
                    ),)
                break
        return ()


class HostSweepDetector(Detector):
    """One source probing many distinct hosts: nmap -sn / ping sweep."""

    sid, name = 1000003, "Network Host Sweep"
    severity, category = "medium", "recon"
    mitre = "T1018"
    cooldown = 30.0

    def __init__(self, threshold: int = 10, window: float = 15.0, **opts: Any) -> None:
        super().__init__(**opts)
        self.threshold = threshold
        self.win = SlidingWindow(window)

    def inspect(self, rec: PacketRecord):
        probe = (
            (rec.proto == "ICMP" and rec.icmp_type == 8)
            or (rec.proto == "TCP" and "S" in rec.tcp_flags and "A" not in rec.tcp_flags)
            or (rec.proto == "ARP" and rec.arp_op == 1)
        )
        if not probe or not rec.src_ip:
            return ()
        self.win.add(rec.src_ip, rec.ts, rec.dst_ip)
        hosts = set(self.win.values(rec.src_ip))
        if len(hosts) >= self.threshold and self._ready(rec.src_ip, rec.ts):
            return (self.alert(
                rec,
                f"probed {len(hosts)} hosts in {self.win.window:.0f}s via {rec.proto}",
                distinct_hosts=len(hosts), method=rec.proto,
                sample_hosts=sorted(hosts)[:15],
            ),)
        return ()

    def gc(self, now: float) -> None:
        self.win.gc(now)


class SynFloodDetector(Detector):
    """High-rate SYN traffic at one service without matching handshakes: DoS."""

    sid, name = 1000004, "SYN Flood / TCP DoS"
    severity, category = "critical", "dos"
    mitre = "T1499.002"
    cooldown = 15.0

    def __init__(self, threshold: int = 200, window: float = 5.0, **opts: Any) -> None:
        super().__init__(**opts)
        self.threshold = threshold
        self.win = SlidingWindow(window)

    def inspect(self, rec: PacketRecord):
        if rec.proto != "TCP" or "S" not in rec.tcp_flags or "A" in rec.tcp_flags:
            return ()
        key = (rec.dst_ip, rec.dst_port)
        dq = self.win.add(key, rec.ts, rec.src_ip)
        if len(dq) >= self.threshold and self._ready(key, rec.ts):
            sources = set(v for _, v in dq)
            rate = len(dq) / max(self.win.window, 0.001)
            spoofed = len(sources) > len(dq) * 0.5
            return (self.alert(
                rec,
                f"{len(dq)} SYNs ({rate:.0f}/s) at {rec.dst_ip}:{rec.dst_port} "
                f"from {len(sources)} source(s)"
                + (" - randomised sources suggest spoofing" if spoofed else ""),
                syn_count=len(dq), rate_per_sec=round(rate, 1),
                distinct_sources=len(sources), likely_spoofed=spoofed,
            ),)
        return ()

    def gc(self, now: float) -> None:
        self.win.gc(now)


class ArpSpoofDetector(Detector):
    """An IP suddenly claimed by a new MAC: ARP cache poisoning / MITM."""

    sid, name = 1000005, "ARP Spoofing / MITM"
    severity, category = "critical", "spoofing"
    mitre = "T1557.002"
    cooldown = 30.0

    def __init__(self, **opts: Any) -> None:
        super().__init__(**opts)
        self.bindings: dict[str, str] = {}
        self.flapping: dict[str, int] = defaultdict(int)

    def inspect(self, rec: PacketRecord):
        if rec.proto != "ARP" or not rec.arp_psrc or not rec.arp_hwsrc:
            return ()
        ip, mac = rec.arp_psrc, rec.arp_hwsrc.lower()
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return ()
        known = self.bindings.get(ip)
        self.bindings[ip] = mac
        if known and known != mac:
            self.flapping[ip] += 1
            if self._ready(ip, rec.ts):
                return (self.alert(
                    rec,
                    f"{ip} moved from {known} to {mac} "
                    f"(change #{self.flapping[ip]})",
                    ip=ip, previous_mac=known, new_mac=mac,
                    changes=self.flapping[ip],
                ),)
        return ()


class BruteForceDetector(Detector):
    """Repeated connection attempts at an authentication service."""

    sid, name = 1000006, "Credential Brute Force"
    severity, category = "high", "exploit"
    mitre = "T1110"
    cooldown = 30.0

    AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3",
                  143: "IMAP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
                  3389: "RDP", 5432: "PostgreSQL", 5900: "VNC"}

    def __init__(self, threshold: int = 25, window: float = 30.0, **opts: Any) -> None:
        super().__init__(**opts)
        self.threshold = threshold
        self.win = SlidingWindow(window)

    def inspect(self, rec: PacketRecord):
        if rec.proto != "TCP" or rec.dst_port not in self.AUTH_PORTS:
            return ()
        if "S" not in rec.tcp_flags or "A" in rec.tcp_flags:
            return ()
        key = (rec.src_ip, rec.dst_ip, rec.dst_port)
        dq = self.win.add(key, rec.ts)
        if len(dq) >= self.threshold and self._ready(key, rec.ts):
            svc = self.AUTH_PORTS[rec.dst_port]
            return (self.alert(
                rec,
                f"{len(dq)} {svc} connections in {self.win.window:.0f}s",
                service=svc, attempts=len(dq),
            ),)
        return ()

    def gc(self, now: float) -> None:
        self.win.gc(now)


class IcmpAnomalyDetector(Detector):
    """Oversized or data-bearing ICMP: tunnelling, exfiltration, ping flood."""

    sid, name = 1000007, "ICMP Anomaly (tunnel / oversized)"
    severity, category = "medium", "policy"
    mitre = "T1048.003"
    cooldown = 20.0

    def __init__(self, max_payload: int = 128, **opts: Any) -> None:
        super().__init__(**opts)
        self.max_payload = max_payload

    def inspect(self, rec: PacketRecord):
        if rec.proto != "ICMP":
            return ()
        size = len(rec.payload)
        if size > self.max_payload:
            key = (rec.src_ip, rec.dst_ip)
            if self._ready(key, rec.ts):
                printable = sum(32 <= b < 127 for b in rec.payload) / max(size, 1)
                return (self.alert(
                    rec,
                    f"ICMP type {rec.icmp_type} carrying {size} bytes "
                    f"({printable:.0%} printable)",
                    payload_bytes=size, printable_ratio=round(printable, 2),
                    preview=rec.payload[:48].hex(),
                ),)
        return ()


class SignatureDetector(Detector):
    """Regex payload signatures loaded from rules/signatures.yaml."""

    sid, name = 1000008, "Payload Signature Match"
    severity, category = "high", "exploit"
    cooldown = 5.0

    def __init__(self, rules: Optional[list[dict]] = None, **opts: Any) -> None:
        super().__init__(**opts)
        self.rules: list[dict] = []
        for r in (rules or []):
            try:
                self.rules.append({
                    "sid": int(r["sid"]),
                    "name": r["name"],
                    "severity": r.get("severity", "high"),
                    "category": r.get("category", "exploit"),
                    "proto": r.get("proto", "any").upper(),
                    "ports": set(r.get("ports", [])) or None,
                    "regex": re.compile(r["regex"].encode(), re.IGNORECASE),
                    "desc": r.get("desc", ""),
                    "mitre": r.get("mitre", "T1190"),
                })
            except (KeyError, re.error) as exc:
                print(f"[rule load error] {r.get('name', '?')}: {exc}")

    def inspect(self, rec: PacketRecord):
        if not rec.payload:
            return ()
        out = []
        for rule in self.rules:
            if rule["proto"] != "ANY" and rule["proto"] != rec.proto:
                continue
            if rule["ports"] and rec.dst_port not in rule["ports"] \
                    and rec.src_port not in rule["ports"]:
                continue
            m = rule["regex"].search(rec.payload)
            if not m:
                continue
            key = (rule["sid"], rec.src_ip, rec.dst_ip)
            if not self._ready(key, rec.ts):
                continue
            snippet = m.group(0)[:80].decode("utf-8", "replace")
            out.append(Alert(
                sid=rule["sid"], name=rule["name"], severity=rule["severity"],
                category=rule["category"], src_ip=rec.src_ip, dst_ip=rec.dst_ip,
                src_port=rec.src_port, dst_port=rec.dst_port, proto=rec.proto,
                detail=f"{rule['desc']} | matched: {snippet!r}",
                evidence={"matched": snippet, "rule_sid": rule["sid"]},
                mitre=rule["mitre"],
            ))
        return out


ALL_DETECTORS = [
    PortScanDetector, StealthScanDetector, HostSweepDetector, SynFloodDetector,
    ArpSpoofDetector, BruteForceDetector, IcmpAnomalyDetector, SignatureDetector,
]
