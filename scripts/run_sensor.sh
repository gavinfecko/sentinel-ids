#!/usr/bin/env bash
# Launch the IDS on the Mac. Needs sudo for live capture.
# Usage: sudo ./scripts/run_sensor.sh [interface] [attacker_ip]
set -euo pipefail
cd "$(dirname "$0")/.."
IFACE="${1:-en0}"
ATTACKER="${2:-}"
FILTER=""
[ -n "$ATTACKER" ] && FILTER="host $ATTACKER"
exec .venv/bin/python -m ids.sensor -i "$IFACE" ${FILTER:+-f "$FILTER"} \
  --min-severity low --log logs/alerts.jsonl --summary-json logs/summary.json
