"""Boundary, cooldown, window-expiry, GC and false-positive behaviour for every
heuristic detector. Records are constructed directly (no scapy), so each test
pins one precise behaviour of the detection logic."""
import pytest
from ids.packet import PacketRecord
from ids.detectors import (
    PortScanDetector, StealthScanDetector, HostSweepDetector, SynFloodDetector,
    ArpSpoofDetector, BruteForceDetector, IcmpAnomalyDetector,
)


def r(ts=0.0, proto="TCP", flags="S", sport=40000, dport=80,
      sip="10.0.0.5", dip="10.0.0.9", payload=b"", itype=None,
      aop=None, apsrc=None, ahw=None):
    return PacketRecord(ts=ts, proto=proto, src_ip=sip, dst_ip=dip,
                        src_port=sport, dst_port=dport, tcp_flags=flags,
                        payload=payload, icmp_type=itype,
                        arp_op=aop, arp_psrc=apsrc, arp_hwsrc=ahw)


def feed(det, recs):
    fired = []
    for rec in recs:
        fired += list(det.inspect(rec))
    return fired


# ---------------- PortScanDetector ----------------

def test_portscan_below_threshold_silent():
    d = PortScanDetector(threshold=15, window=10)
    assert feed(d, [r(ts=i * 0.01, dport=1000 + i) for i in range(14)]) == []

def test_portscan_at_threshold_fires_once():
    d = PortScanDetector(threshold=15, window=10)
    fired = feed(d, [r(ts=i * 0.01, dport=1000 + i) for i in range(15)])
    assert len(fired) == 1 and fired[0].sid == 1000001

def test_portscan_ignores_synack_responses():
    d = PortScanDetector(threshold=15, window=10)
    # SYN-ACK are server responses, not scan probes — must never count
    assert feed(d, [r(ts=i * 0.01, dport=1000 + i, flags="SA") for i in range(25)]) == []

def test_portscan_cooldown_suppresses_immediate_repeat():
    d = PortScanDetector(threshold=15, window=10)
    feed(d, [r(ts=i * 0.01, dport=1000 + i) for i in range(15)])       # fires
    extra = feed(d, [r(ts=i * 0.01, dport=1000 + i) for i in range(15, 40)])
    assert extra == []                                                 # within cooldown

def test_portscan_window_expiry_prevents_slow_scan_falsealarm():
    d = PortScanDetector(threshold=15, window=10)
    # one port every 2s: never 15 distinct within a 10s window
    assert feed(d, [r(ts=i * 2.0, dport=1000 + i) for i in range(30)]) == []

def test_portscan_gc_frees_state():
    d = PortScanDetector(threshold=15, window=10)
    feed(d, [r(ts=i * 0.01, dport=1000 + i) for i in range(15)])
    d.gc(now=10_000.0)
    assert len(d.win.events) == 0


# ---------------- HostSweepDetector ----------------

def test_hostsweep_counts_icmp_tcp_arp_probes():
    d = HostSweepDetector(threshold=10, window=15)
    recs = [r(ts=i * 0.01, proto="ICMP", itype=8, dip=f"10.0.0.{i}") for i in range(10)]
    fired = feed(d, recs)
    assert fired and fired[0].sid == 1000003

def test_hostsweep_ignores_echo_replies():
    d = HostSweepDetector(threshold=10, window=15)
    # ICMP echo REPLY (type 0) is a response, not a sweep probe
    assert feed(d, [r(ts=i * 0.01, proto="ICMP", itype=0, dip=f"10.0.0.{i}") for i in range(15)]) == []

def test_hostsweep_below_threshold_silent():
    d = HostSweepDetector(threshold=10, window=15)
    assert feed(d, [r(ts=i * 0.01, proto="ICMP", itype=8, dip=f"10.0.0.{i}") for i in range(9)]) == []


# ---------------- SynFloodDetector ----------------

def test_synflood_fires_at_threshold():
    d = SynFloodDetector(threshold=200, window=5)
    fired = feed(d, [r(ts=i * 0.001, sport=1024 + i) for i in range(200)])
    assert fired and fired[0].sid == 1000004

def test_synflood_flags_randomised_sources_as_spoofed():
    d = SynFloodDetector(threshold=200, window=5)
    recs = [r(ts=i * 0.001, sip=f"10.{i%250}.{(i//250)%250}.{i%254+1}", sport=1024 + i)
            for i in range(200)]
    fired = feed(d, recs)
    assert fired and fired[0].evidence["likely_spoofed"] is True

def test_synflood_single_source_not_spoofed():
    d = SynFloodDetector(threshold=200, window=5)
    fired = feed(d, [r(ts=i * 0.001, sip="10.0.0.5", sport=1024 + i) for i in range(200)])
    assert fired and fired[0].evidence["likely_spoofed"] is False


# ---------------- BruteForceDetector ----------------

def test_bruteforce_fires_on_auth_port():
    d = BruteForceDetector(threshold=25, window=30)
    fired = feed(d, [r(ts=i * 0.1, dport=22, sport=41000 + i) for i in range(25)])
    assert fired and fired[0].sid == 1000006 and fired[0].evidence["service"] == "SSH"

def test_bruteforce_ignores_non_auth_ports():
    d = BruteForceDetector(threshold=25, window=30)
    # port 8080 is not an auth service — many connects must not be brute force
    assert feed(d, [r(ts=i * 0.1, dport=8080, sport=41000 + i) for i in range(40)]) == []

def test_bruteforce_below_threshold_silent():
    d = BruteForceDetector(threshold=25, window=30)
    assert feed(d, [r(ts=i * 0.1, dport=22, sport=41000 + i) for i in range(24)]) == []


# ---------------- ArpSpoofDetector ----------------

def test_arpspoof_first_binding_is_learned_silently():
    d = ArpSpoofDetector()
    assert list(d.inspect(r(proto="ARP", aop=2, apsrc="10.0.0.1", ahw="aa:aa:aa:aa:aa:aa"))) == []

def test_arpspoof_rebinding_alerts():
    d = ArpSpoofDetector()
    d.inspect(r(ts=1, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="aa:aa:aa:aa:aa:aa"))
    fired = list(d.inspect(r(ts=2, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="bb:bb:bb:bb:bb:bb")))
    assert fired and fired[0].sid == 1000005

def test_arpspoof_same_mac_reannounce_is_silent():
    d = ArpSpoofDetector()
    d.inspect(r(ts=1, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="aa:aa:aa:aa:aa:aa"))
    again = list(d.inspect(r(ts=2, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="aa:aa:aa:aa:aa:aa")))
    assert again == []

def test_arpspoof_ignores_broadcast_and_zero_mac():
    d = ArpSpoofDetector()
    d.inspect(r(ts=1, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="aa:aa:aa:aa:aa:aa"))
    assert list(d.inspect(r(ts=2, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="ff:ff:ff:ff:ff:ff"))) == []
    assert list(d.inspect(r(ts=3, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="00:00:00:00:00:00"))) == []


# ---------------- IcmpAnomalyDetector ----------------

def test_icmp_small_payload_silent():
    d = IcmpAnomalyDetector(max_payload=128)
    assert list(d.inspect(r(proto="ICMP", itype=8, payload=b"x" * 56))) == []

def test_icmp_oversized_payload_alerts_with_printable_ratio():
    d = IcmpAnomalyDetector(max_payload=128)
    fired = list(d.inspect(r(proto="ICMP", itype=8, payload=b"A" * 400)))
    assert fired and fired[0].sid == 1000007
    assert fired[0].evidence["printable_ratio"] == 1.0

def test_icmp_boundary_exactly_at_max_is_silent():
    d = IcmpAnomalyDetector(max_payload=128)
    assert list(d.inspect(r(proto="ICMP", itype=8, payload=b"x" * 128))) == []


# ---------------- generic cooldown ----------------

def test_cooldown_then_refire_after_window():
    d = ArpSpoofDetector()          # cooldown = 30s
    d.inspect(r(ts=0, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="aa:aa:aa:aa:aa:aa"))
    first = list(d.inspect(r(ts=1, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="bb:bb:bb:bb:bb:bb")))
    within = list(d.inspect(r(ts=5, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="cc:cc:cc:cc:cc:cc")))
    after = list(d.inspect(r(ts=40, proto="ARP", aop=2, apsrc="10.0.0.1", ahw="dd:dd:dd:dd:dd:dd")))
    assert first and not within and after
