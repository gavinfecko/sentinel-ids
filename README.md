# sentinel-ids

A signature + heuristic **Network Intrusion Detection System**, built from scratch
in Python, with a matched Kali Linux attack playbook. Home-lab / educational project.

The IDS sniffs live traffic (or replays a pcap), normalises each packet, and runs it
through eight stateful detectors plus a regex signature engine. Alerts stream to a
colourised console and to newline-delimited JSON (`logs/alerts.jsonl`) for SIEM ingest.

## Lab topology

```
  ┌─────────────────────────┐         bridged / same LAN         ┌────────────────────────┐
  │  Kali Linux VM           │  192.168.0.x  ───────────────────▶ │  macOS host            │
  │  attacker                │                                    │  target + IDS sensor   │
  │  nmap · hydra · hping3   │        attack traffic              │  sniffs en0            │
  │  nikto · sqlmap · curl   │ ─────────────────────────────────▶ │  sentinel-ids          │
  └─────────────────────────┘                                    └────────────────────────┘
```

Both machines sit on the same `192.168.0.0/24` LAN (VirtualBox bridged adapter), so
the Mac's `en0` sees the attacker's traffic directly.

## What it detects

| SID      | Detector                  | Severity | Technique / MITRE-ish                 |
|----------|---------------------------|----------|---------------------------------------|
| 1000001  | TCP Port Scan             | high     | nmap -sS/-sT (many ports, one host)   |
| 1000002  | Stealth Scan              | high     | NULL / FIN / XMAS / Maimon flags      |
| 1000003  | Host Sweep                | medium   | nmap -sn ping/ARP sweep               |
| 1000004  | SYN Flood / DoS           | critical | hping3 --flood, spoofed sources       |
| 1000005  | ARP Spoofing / MITM       | critical | ARP cache poisoning (IP↔MAC flap)     |
| 1000006  | Credential Brute Force    | high     | hydra against SSH/FTP/RDP/… ports     |
| 1000007  | ICMP Anomaly              | medium   | oversized / data-bearing ICMP tunnel  |
| 2000001+ | Payload signatures (16)   | varies   | SQLi, XSS, traversal, cmd-injection,  |
|          |                           |          | Log4Shell, Shellshock, reverse shells,|
|          |                           |          | nikto/sqlmap/hydra tool fingerprints  |

## Quick start

```bash
make setup          # create .venv, install scapy/pyyaml/rich/pytest
make test           # 13 unit + integration tests
make replay         # generate a synthetic attack pcap and run the IDS over it (no root)
```

`make replay` proves every detector fires against a crafted pcap and that benign
traffic stays silent — no root, no VM needed.

## Running it live against Kali

**1. On the Mac — start the sensor** (root is required to capture packets):

```bash
sudo .venv/bin/python -m ids.sensor -i en0 --min-severity low
# or scope to just the attacker:
sudo .venv/bin/python -m ids.sensor -i en0 -f "host <KALI_IP>"
```

**2. In the Kali VM — launch attacks** at the Mac's IP (`192.168.0.166`):

```bash
# copy scripts/kali_attacks.sh into the VM, then:
./kali_attacks.sh 192.168.0.166 all
# or one scenario at a time:
./kali_attacks.sh 192.168.0.166 portscan
./kali_attacks.sh 192.168.0.166 web
```

Watch the alerts appear on the Mac in real time. Every run appends to
`logs/alerts.jsonl` and prints a summary (packets, protocols, alert counts,
top talkers) on Ctrl-C.

## Architecture

```
ids/
  packet.py      scapy frame  -> flat PacketRecord (proto, ports, flags, payload)
  detectors.py   SlidingWindow + 8 stateful detectors, cooldown-throttled
  alerts.py      Alert dataclass, AlertBus fan-out, Console + JSONL sinks
  engine.py      owns detectors, feeds packets, tracks stats, periodic GC
  sensor.py      CLI: live sniff or pcap replay, BPF filter, run summary
rules/
  signatures.yaml   16 regex payload signatures (web attacks, tooling, shells)
scripts/
  gen_attack_pcap.py  synthesise a validation pcap of every attack
  kali_attacks.sh     attack playbook to run from the Kali VM
  run_sensor.sh       host-side launcher wrapper
tests/
  test_ids.py         13 tests: parsing, each detector, zero-false-positive
```

Design notes:
- **Stateful detection** uses per-key sliding time windows; keys and events are
  garbage-collected every 30s so memory stays bounded on a busy link.
- **Cooldowns** suppress alert floods — one port scan yields one alert, not 500.
- **Sinks never crash the sensor**: a broken output is caught and logged.
- **SYN-flood spoof heuristic**: if distinct sources ≈ packet count, sources are
  flagged as randomised/spoofed.

## Scope & ethics

Runs only against machines you own on an isolated lab LAN. The attack scripts target
an IP you pass explicitly. Do not point them at systems you are not authorised to test.
