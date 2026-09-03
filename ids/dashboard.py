"""Live terminal dashboard: real-time alert feed + rolling stats, built on rich."""
from __future__ import annotations

import argparse
import signal
import time
from collections import Counter, deque
from pathlib import Path

from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.utils import rdpcap

from .alerts import AlertBus, JsonlSink, SEVERITY_STYLE, SEVERITY_ORDER
from .engine import Engine


class DashboardSink:
    """Collects alerts for the live view instead of printing them line by line."""

    def __init__(self, maxlen: int = 15) -> None:
        self.recent: deque = deque(maxlen=maxlen)
        self.by_sev: Counter = Counter()
        self.by_name: Counter = Counter()
        self.talkers: Counter = Counter()
        self.total = 0

    def write(self, alert) -> None:
        self.recent.appendleft(alert)
        self.by_sev[alert.severity] += 1
        self.by_name[alert.name] += 1
        if alert.src_ip:
            self.talkers[alert.src_ip] += 1
        self.total += 1


def build_layout(engine: Engine, sink: DashboardSink, source: str, started: float):
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich import box

    summary = engine.summary()
    elapsed = time.time() - started

    # header
    head = Text()
    head.append("  🛡  sentinel-ids  ", style="bold white on blue")
    head.append(f"  source: {source}   ", style="cyan")
    head.append(f"uptime: {elapsed:5.0f}s   ", style="dim")
    head.append(f"packets: {summary['packets']}  ({summary['packets_per_sec']}/s)   ",
                style="green")
    head.append(f"alerts: {sink.total}", style="bold red" if sink.total else "dim")

    # severity counters
    sev = Table.grid(expand=True)
    sev.add_column(justify="center", ratio=1)
    cells = []
    for s in ["critical", "high", "medium", "low", "info"]:
        style = SEVERITY_STYLE.get(s, "white")
        t = Text(f"{sink.by_sev.get(s,0)}\n", style=f"bold {style}")
        t.append(s.upper(), style="dim")
        cells.append(Panel(t, box=box.ROUNDED, padding=(0, 1)))
    sev.add_row(*cells)

    # recent alerts feed
    feed = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False)
    feed.add_column("time", style="dim", width=12)
    feed.add_column("sev", width=9)
    feed.add_column("signature", ratio=3)
    feed.add_column("flow", ratio=3, style="cyan")
    feed.add_column("att&ck", width=11, style="blue")
    for a in sink.recent:
        style = SEVERITY_STYLE.get(a.severity, "white")
        feed.add_row(a.ts[11:23], Text(a.severity.upper(), style=style),
                     a.name, a.flow, a.mitre or "")

    # right column: protocols + top talkers + top signatures
    side = Table.grid(expand=True)
    proto = Table(title="protocols", box=box.MINIMAL, expand=True, title_style="bold")
    proto.add_column("proto"); proto.add_column("n", justify="right")
    for k, v in list(summary["protocols"].items())[:6]:
        proto.add_row(k, str(v))
    talk = Table(title="top talkers", box=box.MINIMAL, expand=True, title_style="bold")
    talk.add_column("src ip"); talk.add_column("alerts", justify="right")
    for k, v in sink.talkers.most_common(6):
        talk.add_row(k, str(v))
    sigs = Table(title="top signatures", box=box.MINIMAL, expand=True, title_style="bold")
    sigs.add_column("name"); sigs.add_column("n", justify="right")
    for k, v in sink.by_name.most_common(6):
        sigs.add_row(k[:26], str(v))
    side.add_row(proto); side.add_row(talk); side.add_row(sigs)

    layout = Layout()
    layout.split_column(
        Layout(Panel(head, box=box.HEAVY, style="on grey11"), size=3, name="head"),
        Layout(sev, size=5, name="sev"),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(Panel(feed, title="[bold]live alert feed", border_style="red"), ratio=2),
        Layout(Panel(side, title="[bold]statistics", border_style="blue"), ratio=1),
    )
    return layout


def main():
    ap = argparse.ArgumentParser(description="sentinel-ids live TUI dashboard")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--interface")
    src.add_argument("-r", "--read")
    ap.add_argument("-f", "--filter", default="")
    ap.add_argument("--config")
    ap.add_argument("--rules", default="rules/signatures.yaml")
    ap.add_argument("--log", default="logs/alerts.jsonl")
    ap.add_argument("--replay-delay", type=float, default=0.02,
                    help="seconds between packets when replaying a pcap")
    args = ap.parse_args()

    from rich.live import Live
    from rich.console import Console

    cfg = {}
    rules_path = args.rules
    if args.config:
        import yaml
        cfg = yaml.safe_load(Path(args.config).read_text()) or {}
        rules_path = cfg.get("rules", args.rules)

    bus = AlertBus()
    dash = DashboardSink()
    bus.add_sink(dash)
    bus.add_sink(JsonlSink(args.log))
    engine = Engine(bus, config=cfg, rules_path=rules_path)
    source = args.interface or args.read
    started = time.time()
    console = Console()

    stop = {"flag": False}
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("flag", True))

    with Live(build_layout(engine, dash, source, started),
              console=console, refresh_per_second=8, screen=True) as live:
        def pump(pkt):
            engine.process(pkt)
            live.update(build_layout(engine, dash, source, started))
            return stop["flag"]

        if args.read:
            for pkt in rdpcap(args.read):
                engine.process(pkt)
                live.update(build_layout(engine, dash, source, started))
                if stop["flag"]:
                    break
                time.sleep(args.replay_delay)
            # hold the final frame briefly so the demo is readable
            for _ in range(30):
                if stop["flag"]:
                    break
                time.sleep(0.1)
        else:
            conf.sniff_promisc = True
            sniff(iface=args.interface, filter=args.filter or None,
                  prn=pump, store=False, stop_filter=lambda _p: stop["flag"])

    console.print(f"\n[bold]session ended[/bold] — {dash.total} alerts, "
                  f"{engine.summary()['packets']} packets. log: {args.log}")


if __name__ == "__main__":
    main()
