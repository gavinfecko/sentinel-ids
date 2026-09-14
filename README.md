# 🛡️ sentinel-ids

A **network intrusion detection system** built from scratch in Python, paired with a
Kali Linux attack lab that proves each detection end to end. Signature matching plus
stateful traffic heuristics, MITRE ATT&CK–mapped alerts, a live terminal dashboard,
and an auto-generated HTML incident report.

![CI](https://img.shields.io/badge/tests-13%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![detectors](https://img.shields.io/badge/detectors-8-orange)
![signatures](https://img.shields.io/badge/signatures-16-orange)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## What it does

sentinel-ids passively sniffs a network interface (or replays a pcap), normalises every
packet, and runs it through **eight stateful detectors** and a **regex signature engine**.
Alerts stream to a colourised console or a live TUI, land in newline-delimited JSON for
SIEM ingest, and roll up into a shareable HTML report. Every alert is tagged with its
**MITRE ATT&CK technique**.

## Lab topology

```
   ┌───────────────────────────┐        bridged — same LAN         ┌────────────────────────────┐
   │  Kali Linux VM            │   192.168.0.x                      │  macOS host                 │
   │  ── attacker ──           │ ─────────────────────────────────▶│  ── target + IDS sensor ──  │
   │  nmap · hydra · hping3    │        attack traffic              │  sentinel-ids sniffs en0    │
   │  nikto · sqlmap · curl    │ ─────────────────────────────────▶│  → alerts + report          │
   └───────────────────────────┘                                    └────────────────────────────┘
        192.168.0.50                                                       192.168.0.166
```

Both machines share one `192.168.0.0/24` LAN via a VirtualBox bridged adapter, so the
sensor sees the attacker's packets directly. Everything runs on hardware you own.

## Detection coverage

| SID       | Detector                | Sev.     | Technique         | ATT&CK  |
|-----------|-------------------------|----------|-------------------|---------|
| 1000001   | TCP Port Scan           | high     | nmap -sS / -sT    | T1046   |
| 1000002   | Stealth Scan            | high     | NULL/FIN/XMAS/Maimon | T1046 |
| 1000003   | Host Sweep              | medium   | nmap -sn sweep    | T1018   |
| 1000004   | SYN Flood / DoS         | critical | hping3 --flood    | T1499.002 |
| 1000005   | ARP Spoofing / MITM     | critical | ARP cache poison  | T1557.002 |
| 1000006   | Credential Brute Force  | high     | hydra             | T1110   |
| 1000007   | ICMP Anomaly / Tunnel   | medium   | oversized ICMP    | T1048.003 |
| 2000001+  | 16 payload signatures   | varies   | SQLi, XSS, traversal, cmd-injection, Log4Shell, Shellshock, reverse shells, sqlmap/nikto/hydra | T1190, T1059, … |

## Quick start

```bash
make setup     # venv + deps (scapy, pyyaml, rich)
make test      # 13 unit + integration tests
make demo      # replay a synthetic attack pcap -> alerts + HTML report (no root)
```

`make demo` needs no VM and no root: it synthesises one clean example of every attack,
runs the IDS over it, and writes `logs/report.html`. It's the fastest way to see the
whole system work.

## Running it live against Kali

**Terminal 1 — macOS host, start the sensor** (root required to capture packets):

```bash
sudo .venv/bin/python -m ids.sensor  -i en0 --config config/sentinel.yaml   # console
sudo .venv/bin/python -m ids.dashboard -i en0 --config config/sentinel.yaml # live TUI
```

**Terminal 2 — Kali VM, launch attacks** at the host IP:

```bash
./scripts/kali_attacks.sh 192.168.0.166 all
# or one at a time: portscan · stealth · sweep · synflood · brute · web · icmp
```

Watch alerts appear in real time, then build the report:

```bash
.venv/bin/python -m ids.report -o logs/report.html
```

## Outputs

- **Live TUI dashboard** — severity counters, streaming alert feed, rolling stats.
- **HTML incident report** — severity tiles, ATT&CK table (links to attack.mitre.org),
  top talkers, full alert detail. Rendered from any run's `alerts.jsonl`.
- **JSONL alert log** — one JSON object per alert, ready for Splunk/Elastic ingest.

## Validation results

Two live engagements were run and captured (see `docs/` and `logs/`):

1. **Detection run — Kali → host.** Real Nmap, hping3, and web attacks from the Kali VM were
   captured with `dumpcap` to a Wireshark `.pcapng` and independently flagged by the IDS engine.
   Wireshark (`tshark`) and the IDS agree on the same capture: SYN flood, stealth scan, SQL
   injection, and XSS. Artifact: `logs/wireshark_capture.pcapng`.
2. **Penetration test — Kali → Metasploitable 2.** On an isolated internal network, a full
   black-box test enumerated 23 services and exploited two vulnerabilities to root
   (vsftpd 2.3.4 backdoor CVE-2011-2523, and an open bindshell), extracting the root hash from
   `/etc/shadow`. The engagement traffic was captured and the IDS detected the recon and
   exploitation (port scan, NSE probes, Metasploit-payload signature, cleartext credentials).
   Report: `docs/PENTEST_REPORT.html`; evidence: `docs/pentest_evidence.txt`;
   attack script: `scripts/pentest_metasploitable.sh`.

## Architecture

```
ids/
  packet.py       scapy frame  ->  flat PacketRecord (proto, ports, flags, payload, ttl)
  detectors.py    SlidingWindow + 8 cooldown-throttled stateful detectors
  alerts.py       Alert dataclass · AlertBus fan-out · Console + JSONL sinks
  engine.py       owns detectors, feeds packets, tracks stats, periodic GC
  sensor.py       CLI: live sniff or pcap replay, BPF filter, run summary
  dashboard.py    live rich TUI
  report.py       alerts.jsonl -> self-contained HTML incident report
config/sentinel.yaml   tunable thresholds + per-detector enable/disable
rules/signatures.yaml  16 regex payload signatures, each ATT&CK-mapped
scripts/          attack-pcap generator · Kali attack playbook · launchers
tests/            13 tests: parsing, every detector, zero-false-positive guard
```

**Engineering notes**
- **Stateful detection** via per-key sliding time windows; keys and events are
  garbage-collected every 30 s so memory stays bounded on a busy link.
- **Cooldowns** collapse floods — one scan yields one alert, not five hundred.
- **Sinks are isolated** — a failing output is caught and can never crash the sensor.
- **Config-driven** — tune every threshold or disable a detector without touching code.
- **Validated both ways** — the test suite asserts each attack fires *and* that benign
  traffic stays silent (zero false positives).

## Testing

```bash
make test        # pytest: parsing, each detector, false-positive guard
```

CI (GitHub Actions) runs the suite on Python 3.10–3.12, validates every signature regex,
and runs a detection self-check that replays the attack sim and asserts alerts fire.

## Scope & ethics

Runs only against machines you own on an isolated lab LAN. The attack scripts target an
IP you pass explicitly. Do not point them at systems you are not authorised to test.

## License

MIT
