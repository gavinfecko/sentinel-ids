"""Tests for the audit-driven improvements: home_net direction awareness and
external-noise skipping, accurate packets/sec on pcap replay, and the ARP
allowlist (suppress known-good rebinding, flag impersonation of a trusted IP)."""
from ids.netutil import in_net, direction, parse_nets
from ids.alerts import AlertBus
from ids.engine import Engine
from ids.detectors import ArpSpoofDetector
from ids.packet import PacketRecord
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

MAC1, MAC2 = "52:54:00:00:00:01", "52:54:00:00:00:02"
def eth(p):
    return Ether(dst=MAC1, src=MAC2) / p


# ---------- netutil ----------

def test_in_net_and_direction():
    nets = parse_nets(["10.0.0.0/24"])
    assert in_net("10.0.0.9", nets) and not in_net("8.8.8.8", nets)
    assert direction("8.8.8.8", "10.0.0.9", nets) == "inbound"
    assert direction("10.0.0.9", "8.8.8.8", nets) == "outbound"
    assert direction("10.0.0.9", "10.0.0.7", nets) == "internal"
    assert direction("8.8.8.8", "1.1.1.1", nets) == "external"

def test_parse_nets_skips_garbage():
    assert parse_nets(["not-a-cidr", "10.0.0.0/24"]) and len(parse_nets(["x"])) == 0


# ---------- engine: home_net direction + noise skipping ----------

def _scan(src, dst, n=16):
    return [eth(IP(src=src, dst=dst) / TCP(sport=40000 + i, dport=1000 + i, flags="S"))
            for i in range(n)]

def test_engine_skips_external_to_external():
    bus = AlertBus()
    eng = Engine(bus, rules_path="rules/signatures.yaml", home_net=["10.0.0.0/24"])
    for pk in _scan("8.8.8.8", "1.1.1.1"):     # neither endpoint is ours
        eng.process(pk)
    assert bus.count == 0
    assert eng.summary()["skipped_external"] > 0

def test_engine_detects_inbound_and_tags_direction():
    bus = AlertBus()
    seen = []
    bus.add_sink(type("S", (), {"write": lambda self, a: seen.append(a)})())
    eng = Engine(bus, rules_path="rules/signatures.yaml", home_net=["10.0.0.0/24"])
    for pk in _scan("8.8.8.8", "10.0.0.9"):    # inbound scan against us
        eng.process(pk)
    assert any(a.sid == 1000001 for a in seen)
    assert seen[0].evidence.get("direction") == "inbound"

def test_engine_no_homenet_monitors_everything():
    bus = AlertBus()
    eng = Engine(bus, rules_path="rules/signatures.yaml")   # home_net empty
    for pk in _scan("8.8.8.8", "1.1.1.1"):
        eng.process(pk)
    assert bus.count >= 1                                    # external scan still detected


# ---------- engine: accurate packets/sec on replay ----------

def test_packets_per_sec_uses_capture_span():
    bus = AlertBus()
    eng = Engine(bus, rules_path="rules/signatures.yaml")
    # 100 packets spread over 10 seconds of capture time
    for i in range(100):
        pk = eth(IP(src="8.8.8.8", dst="9.9.9.9") / TCP(sport=1, dport=443, flags="PA"))
        pk.time = 1_700_000_000.0 + i * (10.0 / 99)
        eng.process(pk)
    s = eng.summary()
    assert s["capture_span_seconds"] > 9 and s["capture_span_seconds"] < 11
    assert 8 < s["packets_per_sec"] < 12          # ~10/s by capture time, not replay speed


# ---------- ARP allowlist ----------

def test_arp_allowlist_suppresses_known_rebinding():
    d = ArpSpoofDetector(allowlist={"10.0.0.1": "AA:BB:CC:DD:EE:FF"})
    r = PacketRecord(ts=1.0, proto="ARP", arp_op=2,
                     arp_psrc="10.0.0.1", arp_hwsrc="aa:bb:cc:dd:ee:ff")
    assert list(d.inspect(r)) == []               # matches trusted MAC -> silent

def test_arp_allowlist_flags_impersonation_of_trusted_ip():
    d = ArpSpoofDetector(allowlist={"10.0.0.1": "aa:bb:cc:dd:ee:ff"})
    # someone claims the gateway IP with a different MAC
    r = PacketRecord(ts=1.0, proto="ARP", arp_op=2,
                     arp_psrc="10.0.0.1", arp_hwsrc="66:66:66:66:66:66")
    fired = list(d.inspect(r))
    assert fired and fired[0].evidence["impersonation"] is True
    assert "impersonated" in fired[0].detail

def test_arp_allowlist_passed_through_engine_config():
    bus = AlertBus()
    eng = Engine(bus, rules_path="rules/signatures.yaml",
                 config={"detectors": {"arp_spoof": {"allowlist": {"10.0.0.1": "aa:aa:aa:aa:aa:aa"}}}})
    arp = [d for d in eng.detectors if isinstance(d, ArpSpoofDetector)][0]
    assert arp.allowlist == {"10.0.0.1": "aa:aa:aa:aa:aa:aa"}


def test_arp_never_skipped_even_when_external():
    """ARP spoofing must be detected even if the ARP IPs fall outside home_net."""
    from scapy.layers.l2 import ARP
    bus = AlertBus(); seen = []
    bus.add_sink(type("S", (), {"write": lambda self, a: seen.append(a)})())
    eng = Engine(bus, rules_path="rules/signatures.yaml", home_net=["10.0.0.0/24"])
    for mac in ("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"):   # gateway MAC changes = spoof
        pk = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / ARP(
            op=2, psrc="192.168.99.1", hwsrc=mac, pdst="192.168.99.5")
        pk.time = 1.0
        eng.process(pk)
    assert any(a.sid == 1000005 for a in seen), "ARP spoof missed due to direction skip"
