"""Stealth-scan flag detection and, critically, false-positive guards: normal
TCP control packets (handshake, teardown, keepalives, resets) must never be
flagged as scans. Includes the FIN+ACK regression that a normal connection close
was being reported as a Maimon scan."""
import pytest
from ids.packet import PacketRecord, decode_flags
from ids.detectors import StealthScanDetector


def tcp(flags, dport=80, ts=0.0, sip="10.0.0.5", dip="10.0.0.9"):
    return PacketRecord(ts=ts, proto="TCP", src_ip=sip, dst_ip=dip,
                        src_port=40000, dst_port=dport, tcp_flags=flags)


# flag combinations that ARE scans / never occur in a real session
SCAN_FLAGS = ["", "F", "FPU", "SF", "SR", "FPUS"]

@pytest.mark.parametrize("flags", SCAN_FLAGS, ids=[f or "NULL" for f in SCAN_FLAGS])
def test_stealth_scan_variants_fire(flags):
    d = StealthScanDetector()
    fired = list(d.inspect(tcp(flags)))
    assert fired and fired[0].sid == 1000002


# flag combinations that occur in NORMAL traffic and must NOT alert
NORMAL_FLAGS = [
    "S",    # SYN — connection open
    "SA",   # SYN-ACK — server accept
    "A",    # ACK — data ack / keepalive
    "PA",   # PSH-ACK — data segment
    "FA",   # FIN-ACK — normal connection teardown  (regression: was flagged Maimon)
    "RA",   # RST-ACK — reset of an established connection
    "R",    # RST — abrupt reset
    "FPA",  # FIN-PSH-ACK — last data segment + close
]

@pytest.mark.parametrize("flags", NORMAL_FLAGS)
def test_normal_control_flags_no_false_positive(flags):
    d = StealthScanDetector()
    assert list(d.inspect(tcp(flags))) == [], f"normal {flags} wrongly flagged as a scan"


def test_fin_ack_teardown_regression():
    """A full, normal connection close must produce zero stealth-scan alerts."""
    d = StealthScanDetector()
    seq = ["S", "SA", "A", "PA", "A", "FA", "A", "FA", "A"]   # open, data, close
    fired = []
    for i, f in enumerate(seq):
        fired += list(d.inspect(tcp(f, ts=i * 0.1)))
    assert fired == []


def test_flag_order_insensitive():
    """Flags are matched regardless of the order the bits appear in the string."""
    d1, d2 = StealthScanDetector(), StealthScanDetector()
    assert list(d1.inspect(tcp("FPU"))) and list(d2.inspect(tcp("UPF")))


def test_non_tcp_ignored():
    d = StealthScanDetector()
    assert list(d.inspect(PacketRecord(ts=0.0, proto="UDP", tcp_flags=""))) == []


def test_decode_flags_matches_expectations():
    assert decode_flags(0x00) == ""
    assert decode_flags(0x02) == "S"
    assert decode_flags(0x11) == "FA"        # FIN + ACK
    assert decode_flags(0x29) == "FPU"       # FIN + PSH + URG (XMAS)
