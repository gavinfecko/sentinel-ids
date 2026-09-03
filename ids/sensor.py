"""sentinel-ids sensor: capture from a live interface or replay a pcap."""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.utils import rdpcap

from .alerts import AlertBus, ConsoleSink, JsonlSink
from .engine import Engine

BANNER = r"""
   ____             _   _            _   ___ ____  ____
  / ___|  ___ _ __ | |_(_)_ __   ___| | |_ _|  _ \/ ___|
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |  | || | | \___ \
   ___) |  __/ | | | |_| | | | |  __/ |  | || |_| |___) |
  |____/ \___|_| |_|\__|_|_| |_|\___|_| |___|____/|____/
   network intrusion detection  ::  lab sensor
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel-ids",
        description="Signature and heuristic network intrusion detection sensor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo .venv/bin/python -m ids.sensor -i en0\n"
            "  sudo .venv/bin/python -m ids.sensor -i en0 -f 'host 192.168.0.50'\n"
            "  .venv/bin/python -m ids.sensor -r capture.pcap\n"
        ),
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--interface", help="interface to sniff (e.g. en0)")
    src.add_argument("-r", "--read", help="read packets from a pcap file instead")
    p.add_argument("-f", "--filter", default="", help="BPF capture filter")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="stop after N packets (0 = run until Ctrl-C)")
    p.add_argument("-t", "--timeout", type=int, default=0,
                   help="stop after N seconds")
    p.add_argument("--log", default="logs/alerts.jsonl", help="JSONL alert log path")
    p.add_argument("--rules", default="rules/signatures.yaml", help="signature file")
    p.add_argument("--min-severity", default="low",
                   choices=["info", "low", "medium", "high", "critical"],
                   help="minimum severity printed to console")
    p.add_argument("--summary-json", help="write the run summary to this path")
    p.add_argument("--quiet", action="store_true", help="suppress the banner")
    p.add_argument("--no-promisc", action="store_true",
                   help="do not put the interface in promiscuous mode")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.quiet:
        print(BANNER)

    bus = AlertBus()
    bus.add_sink(ConsoleSink(min_severity=args.min_severity))
    bus.add_sink(JsonlSink(args.log))
    engine = Engine(bus, rules_path=args.rules)

    source = args.interface or args.read
    print(f"  source      : {source}")
    print(f"  detectors   : {len(engine.detectors)} "
          f"({engine.signature_count} payload signatures)")
    print(f"  bpf filter  : {args.filter or '(none)'}")
    print(f"  alert log   : {args.log}")
    print(f"  console min : {args.min_severity}")
    print("-" * 72)

    stop = {"flag": False}

    def handle_sigint(_sig, _frm):
        stop["flag"] = True
        print("\n  stopping sensor...")

    signal.signal(signal.SIGINT, handle_sigint)

    started = time.time()
    try:
        if args.read:
            path = Path(args.read)
            if not path.exists():
                print(f"error: pcap not found: {path}", file=sys.stderr)
                return 2
            for pkt in rdpcap(str(path)):
                engine.process(pkt)
                if stop["flag"]:
                    break
        else:
            conf.sniff_promisc = not args.no_promisc
            sniff(
                iface=args.interface,
                filter=args.filter or None,
                prn=engine.process,
                store=False,
                count=args.count or 0,
                timeout=args.timeout or None,
                stop_filter=lambda _p: stop["flag"],
            )
    except PermissionError:
        print("error: packet capture needs root. Re-run with sudo.", file=sys.stderr)
        return 13
    except OSError as exc:
        print(f"error: capture failed on {source}: {exc}", file=sys.stderr)
        return 1

    summary = engine.summary()
    summary["elapsed_seconds"] = round(time.time() - started, 1)

    print("-" * 72)
    print("  RUN SUMMARY")
    print(f"  packets     : {summary['packets']}  "
          f"({summary['packets_per_sec']}/s over {summary['elapsed_seconds']}s)")
    print(f"  bytes       : {summary['bytes']}")
    print(f"  protocols   : {summary['protocols']}")
    print(f"  alerts      : {summary['alerts']}  {summary['alerts_by_severity']}")
    if summary["top_talkers"]:
        top = list(summary["top_talkers"].items())[:5]
        print(f"  top talkers : {', '.join(f'{ip} ({n})' for ip, n in top)}")
    if summary["detector_errors"]:
        print(f"  errors      : {summary['detector_errors']}")
    print(f"  alert log   : {args.log}")

    if args.summary_json:
        Path(args.summary_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary_json).write_text(json.dumps(summary, indent=2))
        print(f"  summary     : {args.summary_json}")

    bus.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
