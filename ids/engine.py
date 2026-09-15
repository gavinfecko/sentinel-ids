"""Engine: owns detectors, feeds packets through them, tracks statistics."""
from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import yaml

from .alerts import Alert, AlertBus
from .detectors import (
    ArpSpoofDetector, BruteForceDetector, Detector, HostSweepDetector,
    IcmpAnomalyDetector, PortScanDetector, SignatureDetector,
    StealthScanDetector, SynFloodDetector,
)
from .packet import PacketRecord, parse
from .netutil import parse_nets, direction

GC_INTERVAL = 30.0


class Engine:
    def __init__(self, bus: AlertBus, config: Optional[dict] = None,
                 rules_path: Optional[str | Path] = None,
                 home_net: Optional[list[str]] = None) -> None:
        self.bus = bus
        self.config = config or {}
        self.home_net = home_net or (self.config.get('home_net') if self.config else None) or []
        self._home_nets = parse_nets(self.home_net)
        self._first_ts = None
        self._last_ts = None
        self.detectors: list[Detector] = []
        self.stats = Counter()
        self.proto_counts = Counter()
        self.talkers = Counter()
        self.started = time.time()
        self._last_gc = self.started
        self._build(rules_path)

    def _build(self, rules_path) -> None:
        cfg = self.config
        specs = [
            (PortScanDetector, "port_scan", {"threshold": 15, "window": 10.0}),
            (StealthScanDetector, "stealth_scan", {}),
            (HostSweepDetector, "host_sweep", {"threshold": 10, "window": 15.0}),
            (SynFloodDetector, "syn_flood", {"threshold": 200, "window": 5.0}),
            (ArpSpoofDetector, "arp_spoof", {}),
            (BruteForceDetector, "brute_force", {"threshold": 25, "window": 30.0}),
            (IcmpAnomalyDetector, "icmp_anomaly", {"max_payload": 128}),
        ]
        for cls, key, defaults in specs:
            opts = {**defaults, **cfg.get("detectors", {}).get(key, {})}
            if opts.pop("enabled", True):
                self.detectors.append(cls(**opts))

        rules: list[dict] = []
        if rules_path and Path(rules_path).exists():
            loaded = yaml.safe_load(Path(rules_path).read_text()) or {}
            rules = loaded.get("signatures", [])
        self.signature_count = len(rules)
        if rules:
            self.detectors.append(SignatureDetector(rules=rules))

    def process(self, pkt) -> list[Alert]:
        """Parse one packet, run every detector, publish any alerts."""
        self.stats["packets"] += 1
        rec = parse(pkt)
        if rec is None:
            self.stats["unparsed"] += 1
            return []
        self.stats["bytes"] += rec.length
        self.proto_counts[rec.proto] += 1
        if rec.src_ip:
            self.talkers[rec.src_ip] += 1
        if self._first_ts is None:
            self._first_ts = rec.ts
        self._last_ts = rec.ts

        # Direction relative to home_net. If home_net is set, external<->external
        # traffic (neither endpoint ours) is noise we skip; everything else is
        # tagged so alerts carry inbound/outbound/internal context.
        dir_ = None
        if self._home_nets:
            dir_ = direction(rec.src_ip, rec.dst_ip, self._home_nets)
            # ARP is always link-local; never drop it or we'd disable spoof detection.
            if dir_ == "external" and rec.proto != "ARP":
                self.stats["skipped_external"] += 1
                return []

        fired: list[Alert] = []
        for det in self.detectors:
            if not det.enabled:
                continue
            try:
                for alert in det.inspect(rec):
                    if dir_:
                        alert.evidence["direction"] = dir_
                    fired.append(alert)
                    self.bus.emit(alert)
            except Exception as exc:
                self.stats["detector_errors"] += 1
                print(f"[detector error] {det.name}: {type(exc).__name__}: {exc}")

        if rec.ts - self._last_gc > GC_INTERVAL:
            self._gc(rec.ts)
        return fired

    def _gc(self, now: float) -> None:
        for det in self.detectors:
            det.gc(now)
        self._last_gc = now

    def summary(self) -> dict[str, Any]:
        elapsed = max(time.time() - self.started, 0.001)
        # Prefer the capture's own timespan so pcap replay reports the true capture
        # rate, not how fast we replayed it. Fall back to wall clock for live/short runs.
        span = (self._last_ts - self._first_ts) if (self._first_ts is not None
                and self._last_ts and self._last_ts > self._first_ts) else 0.0
        rate_base = span if span > 0 else elapsed
        return {
            "elapsed_seconds": round(elapsed, 1),
            "capture_span_seconds": round(span, 1),
            "packets": self.stats["packets"],
            "bytes": self.stats["bytes"],
            "packets_per_sec": round(self.stats["packets"] / max(rate_base, 0.001), 1),
            "skipped_external": self.stats["skipped_external"],
            "alerts": self.bus.count,
            "alerts_by_severity": dict(self.bus.by_severity),
            "alerts_by_sid": dict(self.bus.by_sid),
            "protocols": dict(self.proto_counts.most_common()),
            "top_talkers": dict(self.talkers.most_common(10)),
            "detectors": len(self.detectors),
            "signatures": self.signature_count,
            "detector_errors": self.stats["detector_errors"],
        }
