"""Alert correlation: fold raw alerts into attacker-centric incidents with a
kill-chain timeline and a risk score. Turns a flat alert stream into the kind of
"what happened" narrative a SOC analyst actually triages.

Usage:
    python -m ids.correlate -i logs/alerts.jsonl [-o incidents.html] [--gap 120]
"""
from __future__ import annotations
import argparse, html, json
from dataclasses import dataclass, field
from datetime import datetime

# Lockheed-Martin-style kill chain, collapsed to the phases this IDS can observe.
STAGES = ["Reconnaissance", "Exploitation", "Actions on Objectives", "Impact"]
STAGE_ORDER = {s: i for i, s in enumerate(STAGES)}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_RECON   = {1000001, 1000002, 1000003, 2001001, 2001002, 2001003, 2001004, 2001005}
_EXPLOIT = {2000001, 2000002, 2000003, 2000004, 2000005, 2000006, 2000007,
            2003001, 2003002, 2001006, 1000006}
_ACTIONS = {2002001, 2002002, 2002003, 2003003, 2003004}
_IMPACT  = {1000004, 1000005}
_BY_CAT  = {"recon": "Reconnaissance", "exploit": "Exploitation",
            "backdoor": "Exploitation", "post-exploit": "Actions on Objectives",
            "dos": "Impact", "mitm": "Impact", "spoofing": "Impact"}

def stage_for(sid: int, category: str = "") -> str:
    if sid in _RECON:   return "Reconnaissance"
    if sid in _EXPLOIT: return "Exploitation"
    if sid in _ACTIONS: return "Actions on Objectives"
    if sid in _IMPACT:  return "Impact"
    return _BY_CAT.get(category, "Exploitation")

def _parse_ts(s):
    try: return datetime.fromisoformat(str(s)).timestamp()
    except Exception: return 0.0

@dataclass
class Incident:
    src_ip: str                       # the attacker (initiator of recon/exploit)
    alerts: list = field(default_factory=list)

    @property
    def attacker(self):
        """IP that originated the offense. Recon (scans/sweeps) is definitionally
        attacker-initiated, so it decides; exploitation is the tie-breaker."""
        recon, exploit = {}, {}
        for a in self.alerts:
            st = stage_for(a["sid"], a.get("category", ""))
            ip = a.get("src_ip")
            if not ip:
                continue
            if st == "Reconnaissance":
                recon[ip] = recon.get(ip, 0) + 1
            elif st == "Exploitation":
                exploit[ip] = exploit.get(ip, 0) + 1
        if recon:
            return max(recon, key=recon.get)
        if exploit:
            return max(exploit, key=exploit.get)
        return self.src_ip
    @property
    def targets(self):
        atk = self.attacker
        ips = {a.get("src_ip") for a in self.alerts} | {a.get("dst_ip") for a in self.alerts}
        return sorted(ip for ip in ips if ip and ip != atk)
    @property
    def first(self): return min(_parse_ts(a["ts"]) for a in self.alerts)
    @property
    def last(self):  return max(_parse_ts(a["ts"]) for a in self.alerts)
    @property
    def techniques(self): return sorted({a["mitre"] for a in self.alerts if a.get("mitre")})
    @property
    def stages(self):
        seen = {stage_for(a["sid"], a.get("category", "")) for a in self.alerts}
        return sorted(seen, key=lambda s: STAGE_ORDER.get(s, 9))
    @property
    def max_sev(self):
        return max(self.alerts, key=lambda a: SEV_RANK.get(a["severity"], 0))["severity"]
    @property
    def score(self):
        """Risk score = severity weight of alerts + bonus for kill-chain progression."""
        sev = sum(SEV_RANK.get(a["severity"], 0) for a in self.alerts)
        prog = len(self.stages) * 5
        reached_actions = 15 if self.stages and STAGE_ORDER[self.stages[-1]] >= 2 else 0
        return sev + prog + reached_actions
    def summary_line(self):
        return (f"{self.attacker} -> {','.join(self.targets) or '?'} | "
                f"{len(self.alerts)} alerts | sev={self.max_sev} | "
                f"stages={'->'.join(self.stages)} | risk={self.score}")

def correlate(alerts, gap=120.0):
    """Group alerts by attacker; split one attacker's alerts into separate
    incidents when the idle gap between consecutive alerts exceeds `gap` seconds."""
    by_pair = {}
    for a in alerts:
        key = frozenset(x for x in (a.get("src_ip"), a.get("dst_ip")) if x) or frozenset({"unknown"})
        by_pair.setdefault(key, []).append(a)
    incidents = []
    for src, items in by_pair.items():
        items.sort(key=lambda a: _parse_ts(a["ts"]))
        cur = Incident(src, [items[0]])
        for prev, a in zip(items, items[1:]):
            if _parse_ts(a["ts"]) - _parse_ts(prev["ts"]) > gap:
                incidents.append(cur); cur = Incident(src, [a])
            else:
                cur.add(a) if hasattr(cur, "add") else cur.alerts.append(a)
        incidents.append(cur)
    incidents.sort(key=lambda i: i.score, reverse=True)
    return incidents

def load(path):
    with open(path) as fh:
        return [json.loads(l) for l in fh if l.strip()]

def render_html(incidents, title="Incident Correlation"):
    sev_c = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#3b82f6", "low": "#22c55e", "info": "#64748b"}
    def esc(x): return html.escape(str(x))
    cards = []
    for n, inc in enumerate(incidents, 1):
        chain = ""
        for st in STAGES:
            on = st in inc.stages
            chain += (f'<span style="padding:3px 10px;border-radius:14px;margin-right:6px;font-size:12px;'
                      f'background:{"#7c3aed" if on else "#232833"};color:{"#fff" if on else "#5b6472"}">{esc(st)}</span>')
        rows = ""
        for a in sorted(inc.alerts, key=lambda a: _parse_ts(a["ts"])):
            c = sev_c.get(a["severity"], "#888")
            rows += (f'<tr><td style="color:#9aa4b2;font:12px monospace">{esc(a["ts"][11:19])}</td>'
                     f'<td><span style="color:{c};font-weight:600">{esc(a["severity"])}</span></td>'
                     f'<td>{esc(a["name"])}</td><td style="font:12px monospace;color:#7c3aed">{esc(a.get("mitre",""))}</td>'
                     f'<td style="font:12px monospace">{esc(a.get("dst_ip",""))}:{esc(a.get("dst_port",""))}</td></tr>')
        cards.append(f'''<div style="background:#171a21;border:1px solid #262b34;border-radius:12px;padding:18px;margin:14px 0">
<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px">
<div><b style="font-size:17px">Incident #{n} — attacker {esc(inc.attacker)}</b><br>
<span style="color:#9aa4b2;font-size:13px">targets: {esc(", ".join(inc.targets) or "?")} &middot; {len(inc.alerts)} alerts &middot; techniques: {esc(", ".join(inc.techniques))}</span></div>
<div style="text-align:right"><span style="font-size:26px;font-weight:800;color:{sev_c.get(inc.max_sev)}">{inc.score}</span><br><span style="color:#9aa4b2;font-size:11px">RISK SCORE</span></div>
</div>
<div style="margin:12px 0">{chain}</div>
<table style="width:100%;border-collapse:collapse;font-size:13px">
<tr style="color:#9aa4b2;font-size:11px;text-transform:uppercase"><th style="text-align:left">Time</th><th style="text-align:left">Sev</th><th style="text-align:left">Signature</th><th style="text-align:left">ATT&CK</th><th style="text-align:left">Target</th></tr>
{rows}</table></div>''')
    return f'''<!doctype html><meta charset="utf-8"><title>{esc(title)}</title>
<body style="margin:0;background:#0f1115;color:#e7ebf0;font:15px -apple-system,Segoe UI,Roboto,sans-serif">
<div style="max-width:900px;margin:0 auto;padding:36px 20px">
<h1 style="margin:0 0 4px">{esc(title)}</h1>
<p style="color:#9aa4b2;margin:0 0 20px">{len(incidents)} incident(s) correlated from the alert stream, ranked by risk score.</p>
{"".join(cards)}
<p style="color:#5b6472;font-size:12px;margin-top:30px">Generated by sentinel-ids correlation engine.</p>
</div></body>'''

def main(argv=None):
    ap = argparse.ArgumentParser(description="Correlate IDS alerts into incidents")
    ap.add_argument("-i", "--input", default="logs/alerts.jsonl")
    ap.add_argument("-o", "--output", help="write an HTML incident report here")
    ap.add_argument("--gap", type=float, default=120.0, help="session idle gap (s)")
    ap.add_argument("-t", "--title", default="Incident Correlation")
    args = ap.parse_args(argv)
    incidents = correlate(load(args.input), gap=args.gap)
    print(f"{len(incidents)} incident(s) from {args.input}:\n")
    for n, inc in enumerate(incidents, 1):
        print(f"  #{n}  {inc.summary_line()}")
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(render_html(incidents, args.title))
        print(f"\nwrote {args.output}")

if __name__ == "__main__":
    main()
