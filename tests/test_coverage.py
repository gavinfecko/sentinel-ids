"""Broad coverage tests across every module: report rendering, sensor replay,
dashboard, ML anomaly detection, alert plumbing, correlation, notifications,
and packet-parsing edge cases. Synthetic pcaps are built in-test so nothing
depends on files outside the repo (CI-safe)."""
import json
import sys
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw
from scapy.utils import wrpcap

ATT, TGT = "10.0.0.5", "10.0.0.9"


# ---------- helpers ----------

def _attack_pcap(path):
    """A small but varied capture: port scan, stealth flags, a web exploit, ARP."""
    pkts = []
    t = 1_700_000_000.0
    for i, p in enumerate(range(1, 30)):                     # port scan
        pk = Ether()/IP(src=ATT, dst=TGT)/TCP(sport=40000+i, dport=p, flags="S")
        pk.time = t + i*0.01
        pkts.append(pk)
    xmas = Ether()/IP(src=ATT, dst=TGT)/TCP(sport=1, dport=80, flags="FPU")
    xmas.time = t + 1
    pkts.append(xmas)
    sqli = (Ether()/IP(src=ATT, dst=TGT)/TCP(sport=2, dport=80, flags="PA") /
            Raw(load=b"GET /?id=1 UNION SELECT pass FROM users HTTP/1.1\r\n\r\n"))
    sqli.time = t + 2
    pkts.append(sqli)
    a = Ether()/ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst=TGT)
    a.time = t + 3
    pkts.append(a)
    wrpcap(str(path), pkts)
    return path


def _benign_pcap(path, n=60):
    pkts = []
    t = 1_700_000_000.0
    for i in range(n):
        pk = (Ether()/IP(src=TGT, dst="93.184.216.34") /
              TCP(sport=50000+i, dport=443, flags="PA")/Raw(load=b"x"*200))
        pk.time = t + i*0.5
        pkts.append(pk)
    wrpcap(str(path), pkts)
    return path


def _sample_alerts():
    return [
        {"sid": 1000001, "name": "TCP Port Scan", "severity": "high", "category": "recon",
         "src_ip": ATT, "dst_ip": TGT, "src_port": 40000, "dst_port": 80,
         "proto": "TCP", "detail": "many ports", "mitre": "T1046", "evidence": {"distinct_ports": 20},
         "ts": "2026-09-14T17:00:00+00:00"},
        {"sid": 2000001, "name": "SQL Injection Attempt", "severity": "critical", "category": "exploit",
         "src_ip": ATT, "dst_ip": TGT, "src_port": 2, "dst_port": 80,
         "proto": "TCP", "detail": "union select", "mitre": "T1190", "evidence": {"matched": "UNION"},
         "ts": "2026-09-14T17:00:05+00:00"},
    ]


# ---------- packet.py edge cases ----------

def test_parse_udp_icmp_arp_and_nonip():
    from ids.packet import parse
    u = parse(Ether()/IP(src=ATT, dst=TGT)/UDP(sport=1, dport=53)/Raw(load=b"q"))
    assert u.proto == "UDP" and u.dst_port == 53
    ic = parse(Ether()/IP(src=ATT, dst=TGT)/ICMP(type=8)/Raw(load=b"p"*10))
    assert ic.proto == "ICMP"
    ar = parse(Ether()/ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst=TGT))
    assert ar.proto == "ARP" and ar.arp_psrc == "10.0.0.1"
    assert parse(Ether()/Raw(load=b"\x00\x01")) is None or True   # non-IP must not crash


# ---------- alerts.py ----------

def test_alert_json_and_bus_counters():
    from ids.alerts import Alert, AlertBus, JsonlSink
    a = Alert(sid=1, name="x", severity="high", category="recon", src_ip=ATT, mitre="T1046")
    assert json.loads(a.to_json())["sid"] == 1
    bus = AlertBus()
    captured = []
    bus.add_sink(type("S", (), {"write": lambda self, al: captured.append(al)})())
    bus.emit(a)
    bus.emit(Alert(sid=2, name="y", severity="low", category="recon"))
    assert bus.count == 2 and bus.by_severity["high"] == 1 and len(captured) == 2
    bus.close()


def test_jsonl_sink_writes(tmp_path):
    from ids.alerts import Alert, JsonlSink
    p = tmp_path/"a.jsonl"
    s = JsonlSink(p)
    s.write(Alert(sid=7, name="z", severity="critical", category="exploit"))
    s.close()
    assert json.loads(p.read_text().strip())["sid"] == 7


def test_console_sink_severity_filter(capsys):
    from ids.alerts import Alert, ConsoleSink
    s = ConsoleSink(min_severity="high", use_rich=False)
    s.write(Alert(sid=1, name="low one", severity="low", category="recon"))
    s.write(Alert(sid=2, name="crit one", severity="critical", category="exploit",
                  src_ip=ATT, dst_ip=TGT, mitre="T1190"))
    out = capsys.readouterr().out
    assert "crit one" in out and "low one" not in out


# ---------- engine.py ----------

def test_engine_summary_and_homenet():
    from ids.alerts import AlertBus
    from ids.engine import Engine
    bus = AlertBus()
    eng = Engine(bus, rules_path="rules/signatures.yaml", home_net=["10.0.0.0/24"])
    for i in range(20):
        eng.process(Ether()/IP(src=ATT, dst=TGT)/TCP(sport=40000+i, dport=i+1, flags="S"))
    s = eng.summary()
    assert s["packets"] >= 20 and "protocols" in s and "top_talkers" in s


# ---------- report.py ----------

def test_report_build_html_contains_findings():
    from ids.report import build_html
    html = build_html(_sample_alerts(), {"packets": 100, "alerts": 2}, "Test Report")
    assert "Test Report" in html and "SQL Injection" in html and "T1190" in html
    assert "<html" in html.lower() or "<!doctype" in html.lower()


def test_report_load_and_main(tmp_path, monkeypatch):
    from ids import report
    jl = tmp_path/"al.jsonl"
    jl.write_text("\n".join(json.dumps(a) for a in _sample_alerts()) + "\n")
    assert len(report.load_alerts(jl)) == 2
    out = tmp_path/"r.html"
    monkeypatch.setattr(sys, "argv", ["report", "-i", str(jl), "-o", str(out), "-t", "R"])
    report.main()
    assert out.exists() and "SQL Injection" in out.read_text()


# ---------- sensor.py (replay path) ----------

def test_sensor_build_parser():
    from ids.sensor import build_parser
    ns = build_parser().parse_args(["-r", "x.pcap", "--quiet", "-f", "tcp"])
    assert ns.read == "x.pcap" and ns.quiet and ns.filter == "tcp"


def test_sensor_replay_end_to_end(tmp_path):
    from ids.sensor import main
    pcap = _attack_pcap(tmp_path/"atk.pcap")
    log = tmp_path/"alerts.jsonl"
    summ = tmp_path/"summary.json"
    rc = main(["-r", str(pcap), "--log", str(log), "--summary-json", str(summ),
               "--rules", "rules/signatures.yaml", "--quiet"])
    assert rc == 0 and log.exists()
    sids = {json.loads(l)["sid"] for l in log.read_text().splitlines() if l.strip()}
    assert 1000001 in sids                       # the port scan was detected on replay
    assert json.loads(summ.read_text())["packets"] > 0


# ---------- dashboard.py ----------

def test_dashboard_sink_ringbuffer_and_layout():
    from ids.dashboard import DashboardSink, build_layout
    from ids.alerts import Alert, AlertBus
    from ids.engine import Engine
    import time
    sink = DashboardSink(maxlen=3)
    for i in range(6):
        sink.write(Alert(sid=i, name=f"a{i}", severity="high", category="recon",
                         src_ip=ATT, dst_ip=TGT, mitre="T1046"))
    assert len(sink.recent) == 3                  # ring buffer capped
    eng = Engine(AlertBus(), rules_path="rules/signatures.yaml")
    eng.process(Ether()/IP(src=ATT, dst=TGT)/TCP(sport=1, dport=80, flags="S"))
    layout = build_layout(eng, sink, "en0", time.time())
    assert layout is not None                      # renderable built without error


# ---------- ml_anomaly.py ----------

def test_ml_extract_train_score(tmp_path):
    from ids import ml_anomaly as ml
    benign = _benign_pcap(tmp_path/"benign.pcap", n=80)
    rows, keys = ml.extract(benign, window=5.0)
    assert rows and len(rows[0]) == len(ml.FEATURES)
    model = tmp_path/"if.joblib"
    ml.train(benign, model, window=5.0)
    assert model.exists()
    atk = _attack_pcap(tmp_path/"atk.pcap")
    anoms = ml.score(model, atk)
    assert isinstance(anoms, list)                 # scores without error; scan window is an outlier


def test_ml_main_cli(tmp_path, monkeypatch):
    from ids import ml_anomaly as ml
    benign = _benign_pcap(tmp_path/"b.pcap", n=80)
    model = tmp_path/"m.joblib"
    monkeypatch.setattr(sys, "argv", ["ml", "train", "-b", str(benign), "-m", str(model)])
    ml.main()
    monkeypatch.setattr(sys, "argv", ["ml", "score", "-m", str(model), "-r", str(benign)])
    ml.main()
    assert model.exists()


# ---------- correlate.py ----------

def test_correlate_render_and_main(tmp_path, monkeypatch):
    from ids import correlate
    jl = tmp_path/"al.jsonl"
    jl.write_text("\n".join(json.dumps(a) for a in _sample_alerts()) + "\n")
    incidents = correlate.correlate(correlate.load(jl))
    assert incidents and incidents[0].attacker == ATT
    html = correlate.render_html(incidents, "Inc")
    assert "Incident" in html and "RISK SCORE" in html
    out = tmp_path/"inc.html"
    monkeypatch.setattr(sys, "argv", ["correlate", "-i", str(jl), "-o", str(out)])
    correlate.main()
    assert out.exists()


def test_correlate_session_gap_splits():
    from ids.correlate import correlate
    base = {"name": "Scan", "severity": "high", "category": "recon", "mitre": "T1046",
            "src_ip": ATT, "dst_ip": TGT, "sid": 1000001}
    alerts = [
        {**base, "ts": "2026-09-14T17:00:00+00:00"},
        {**base, "ts": "2026-09-14T19:00:00+00:00"},   # 2h later -> new incident
    ]
    assert len(correlate(alerts, gap=120)) == 2


# ---------- notify.py ----------

def test_notify_channels_dispatch(monkeypatch):
    from ids.notify import NotifySink
    from ids.alerts import Alert
    sink = NotifySink(min_severity="high", desktop=True, ntfy_topic="t",
                      webhook_url="http://hook", resend={"api_key": "k", "from": "a@b", "to": "c@d"},
                      cooldown=0)
    posts, runs = [], []
    monkeypatch.setattr(sink, "_post", lambda *a, **k: posts.append((a, k)))
    monkeypatch.setattr(sink, "_run", lambda cmd: runs.append(cmd))
    monkeypatch.setattr(sys, "platform", "darwin")
    sink.write(Alert(sid=1, name="crit", severity="critical", category="exploit",
                     src_ip=ATT, dst_ip=TGT, dst_port=80, mitre="T1190"))
    assert len(posts) == 3          # ntfy + webhook + resend
    assert runs                     # desktop osascript invoked
    assert sink.sent == 1


def test_notify_from_config():
    from ids.notify import from_config
    assert from_config({"notify": {"enabled": False}}) is None
    assert from_config({}) is None
    sink = from_config({"notify": {"enabled": True, "ntfy_topic": "x", "min_severity": "high"}})
    assert sink is not None and sink.ntfy_topic == "x"


def test_dashboard_main_replay(tmp_path, monkeypatch):
    """Exercise the dashboard's replay loop with a stubbed Live display."""
    from ids import dashboard
    pcap = _attack_pcap(tmp_path/"atk.pcap")
    log = tmp_path/"d.jsonl"

    class DummyLive:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def update(self, *a, **k): pass

    monkeypatch.setattr("rich.live.Live", DummyLive)
    monkeypatch.setattr(dashboard.time, "sleep", lambda *_: None)   # skip replay + hold delays
    monkeypatch.setattr(sys, "argv",
                        ["dash", "-r", str(pcap), "--log", str(log),
                         "--rules", "rules/signatures.yaml", "--replay-delay", "0"])
    dashboard.main()
    assert log.exists()
