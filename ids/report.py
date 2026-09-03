"""Generate a self-contained HTML incident report from an alerts.jsonl log."""
from __future__ import annotations

import argparse
import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SEV_COLOR = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
    "low": "#2563eb", "info": "#6b7280",
}
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# MITRE technique id -> human name, for the ATT&CK section
MITRE_NAMES = {
    "T1046": "Network Service Discovery", "T1018": "Remote System Discovery",
    "T1499.002": "Endpoint DoS: Service Exhaustion Flood",
    "T1557.002": "AiTM: ARP Cache Poisoning", "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1048.003": "Exfiltration Over Unencrypted Protocol",
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Command Interpreter: Unix Shell",
    "T1059.007": "Command Interpreter: JavaScript",
    "T1083": "File and Directory Discovery",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
    "T1552.001": "Unsecured Credentials: In Files",
    "T1204": "User Execution",
}


def load_alerts(path: Path) -> list[dict]:
    alerts = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return alerts


def esc(x) -> str:
    return html.escape(str(x))


def build_html(alerts: list[dict], summary: dict | None, title: str) -> str:
    by_sev = Counter(a["severity"] for a in alerts)
    by_cat = Counter(a.get("category", "misc") for a in alerts)
    by_name = Counter(a["name"] for a in alerts)
    talkers = Counter(a["src_ip"] for a in alerts if a.get("src_ip"))
    mitre = Counter(a["mitre"] for a in alerts if a.get("mitre"))
    sev_sorted = sorted(by_sev, key=lambda s: -SEV_ORDER.get(s, 0))

    ts_list = sorted(a["ts"] for a in alerts if a.get("ts"))
    span = f"{ts_list[0][:19]} — {ts_list[-1][:19]} UTC" if ts_list else "n/a"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def sev_badge(s):
        return (f'<span class="badge" style="background:{SEV_COLOR.get(s,"#666")}">'
                f'{esc(s.upper())}</span>')

    # KPI tiles
    tiles = "".join(
        f'<div class="tile"><div class="tile-n" style="color:{SEV_COLOR.get(s)}">'
        f'{by_sev[s]}</div><div class="tile-l">{esc(s)}</div></div>'
        for s in sev_sorted)

    # severity bar
    total = max(sum(by_sev.values()), 1)
    bar = "".join(
        f'<div style="width:{by_sev[s]/total*100:.1f}%;background:{SEV_COLOR.get(s)}" '
        f'title="{esc(s)}: {by_sev[s]}"></div>' for s in sev_sorted)

    # alert rows (most severe first, then chronological)
    rows = ""
    for a in sorted(alerts, key=lambda a: (-SEV_ORDER.get(a["severity"], 0), a.get("ts", ""))):
        ev = a.get("evidence", {})
        ev_str = ", ".join(f"{k}={v}" for k, v in list(ev.items())[:4]) if ev else ""
        rows += (
            f'<tr><td class="mono">{esc(a.get("ts","")[11:23])}</td>'
            f'<td>{sev_badge(a["severity"])}</td>'
            f'<td><b>{esc(a["name"])}</b><div class="sub">{esc(a.get("detail",""))}</div></td>'
            f'<td class="mono">{esc(a.get("src_ip","?"))}'
            f'{":"+str(a["src_port"]) if a.get("src_port") else ""}</td>'
            f'<td class="mono">{esc(a.get("dst_ip","?"))}'
            f'{":"+str(a["dst_port"]) if a.get("dst_port") else ""}</td>'
            f'<td class="mono">{esc(a.get("proto",""))}</td>'
            f'<td><a href="https://attack.mitre.org/techniques/'
            f'{esc((a.get("mitre") or "").replace(".","/"))}/" target="_blank" '
            f'class="tech">{esc(a.get("mitre",""))}</a></td></tr>')

    def table(counter, headers):
        h = "".join(f"<th>{esc(x)}</th>" for x in headers)
        r = "".join(f"<tr><td>{esc(k)}</td><td class='num'>{v}</td></tr>"
                    for k, v in counter.most_common(12))
        return f"<table class='mini'><tr>{h}</tr>{r}</table>"

    mitre_rows = "".join(
        f'<tr><td class="mono"><a href="https://attack.mitre.org/techniques/'
        f'{esc(t.replace(".","/"))}/" target="_blank" class="tech">{esc(t)}</a></td>'
        f'<td>{esc(MITRE_NAMES.get(t, "—"))}</td><td class="num">{n}</td></tr>'
        for t, n in sorted(mitre.items(), key=lambda x: -x[1]))

    stat = summary or {}
    pkts = stat.get("packets", "—")
    pps = stat.get("packets_per_sec", "—")
    protos = stat.get("protocols", {})
    proto_str = ", ".join(f"{k} {v}" for k, v in protos.items()) if protos else "—"

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<style>
 :root{{--bg:#0b1020;--card:#141b2e;--line:#243049;--fg:#e6ebf5;--mut:#8a97b1}}
 *{{box-sizing:border-box}}
 body{{margin:0;background:var(--bg);color:var(--fg);
   font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
 .wrap{{max-width:1100px;margin:0 auto;padding:32px 20px 64px}}
 header h1{{margin:0 0 4px;font-size:26px;letter-spacing:-.02em}}
 .meta{{color:var(--mut);font-size:13px}}
 .grid{{display:grid;gap:16px}}
 .tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin:24px 0}}
 .tile{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;text-align:center}}
 .tile-n{{font-size:30px;font-weight:700}} .tile-l{{color:var(--mut);text-transform:capitalize;font-size:12px}}
 .bar{{display:flex;height:14px;border-radius:8px;overflow:hidden;margin:8px 0 28px;border:1px solid var(--line)}}
 .bar div{{min-width:2px}}
 section{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0}}
 h2{{font-size:16px;margin:0 0 14px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th{{text-align:left;color:var(--mut);font-weight:600;border-bottom:1px solid var(--line);padding:8px 10px;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
 td{{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
 tr:last-child td{{border-bottom:none}}
 .num{{text-align:right;font-variant-numeric:tabular-nums;color:var(--mut)}}
 .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}}
 .sub{{color:var(--mut);font-size:12px;margin-top:2px;max-width:420px}}
 .badge{{color:#fff;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}}
 .tech{{color:#7dd3fc;text-decoration:none;font-family:ui-monospace,monospace}}
 .tech:hover{{text-decoration:underline}}
 .cols{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
 .mini td:first-child{{color:var(--fg)}}
 @media(max-width:720px){{.cols{{grid-template-columns:1fr}}}}
 footer{{color:var(--mut);font-size:12px;margin-top:32px;text-align:center}}
</style></head><body><div class="wrap">
<header>
 <h1>🛡️ {esc(title)}</h1>
 <div class="meta">Generated {generated} · {len(alerts)} alerts · window: {span}</div>
</header>

<div class="tiles">{tiles}
 <div class="tile"><div class="tile-n">{len(alerts)}</div><div class="tile-l">total alerts</div></div>
 <div class="tile"><div class="tile-n">{pkts}</div><div class="tile-l">packets analysed</div></div>
</div>
<div class="bar">{bar}</div>

<section>
 <h2>Traffic summary</h2>
 <table class="mini">
  <tr><td>Packets analysed</td><td class="num">{pkts}</td></tr>
  <tr><td>Throughput</td><td class="num">{pps} pkt/s</td></tr>
  <tr><td>Protocols</td><td class="num">{esc(proto_str)}</td></tr>
  <tr><td>Distinct alerting sources</td><td class="num">{len(talkers)}</td></tr>
 </table>
</section>

<div class="cols">
 <section><h2>Top alerting sources</h2>{table(talkers, ["Source IP","Alerts"])}</section>
 <section><h2>Alerts by category</h2>{table(by_cat, ["Category","Count"])}</section>
</div>

<section>
 <h2>MITRE ATT&CK® techniques observed</h2>
 <table><tr><th>Technique</th><th>Name</th><th class="num">Alerts</th></tr>{mitre_rows}</table>
</section>

<section>
 <h2>Alert detail ({len(alerts)})</h2>
 <table>
  <tr><th>Time</th><th>Severity</th><th>Signature</th><th>Source</th><th>Destination</th><th>Proto</th><th>ATT&CK</th></tr>
  {rows}
 </table>
</section>

<footer>sentinel-ids · signature + heuristic network intrusion detection · lab report</footer>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Render an HTML report from alerts.jsonl")
    ap.add_argument("-i", "--input", default="logs/alerts.jsonl")
    ap.add_argument("-s", "--summary", default="logs/summary.json")
    ap.add_argument("-o", "--output", default="logs/report.html")
    ap.add_argument("-t", "--title", default="Intrusion Detection Report")
    args = ap.parse_args()

    alerts = load_alerts(Path(args.input))
    summary = None
    if Path(args.summary).exists():
        summary = json.loads(Path(args.summary).read_text())
    Path(args.output).write_text(build_html(alerts, summary, args.title))
    print(f"wrote {args.output}  ({len(alerts)} alerts)")


if __name__ == "__main__":
    main()
