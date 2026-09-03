"""Alert model and output sinks."""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SEVERITY_STYLE = {
    "info": "dim cyan",
    "low": "blue",
    "medium": "yellow",
    "high": "bold red",
    "critical": "bold white on red",
}


@dataclass
class Alert:
    """A single detection event emitted by a detector."""

    sid: int                       # signature id, Snort-style
    name: str                      # short rule name
    severity: str                  # info | low | medium | high | critical
    category: str                  # recon, dos, exploit, policy, spoofing
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @property
    def flow(self) -> str:
        s = self.src_ip or "?"
        d = self.dst_ip or "?"
        if self.src_port:
            s = f"{s}:{self.src_port}"
        if self.dst_port:
            d = f"{d}:{self.dst_port}"
        return f"{s} -> {d}"


class AlertBus:
    """Fans alerts out to every registered sink. Thread-safe."""

    def __init__(self) -> None:
        self._sinks: list[Any] = []
        self._lock = threading.Lock()
        self.count = 0
        self.by_severity: dict[str, int] = {}
        self.by_sid: dict[int, int] = {}

    def add_sink(self, sink: Any) -> None:
        self._sinks.append(sink)

    def emit(self, alert: Alert) -> None:
        with self._lock:
            self.count += 1
            self.by_severity[alert.severity] = self.by_severity.get(alert.severity, 0) + 1
            self.by_sid[alert.sid] = self.by_sid.get(alert.sid, 0) + 1
            for sink in self._sinks:
                try:
                    sink.write(alert)
                except Exception as exc:  # a broken sink must never kill the sensor
                    print(f"[alert sink error] {type(exc).__name__}: {exc}")

    def close(self) -> None:
        for sink in self._sinks:
            if hasattr(sink, "close"):
                try:
                    sink.close()
                except Exception:
                    pass


class JsonlSink:
    """Append alerts as newline-delimited JSON, suitable for SIEM ingest."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")

    def write(self, alert: Alert) -> None:
        self._fh.write(alert.to_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class ConsoleSink:
    """Human-readable colourised console output."""

    def __init__(self, min_severity: str = "low", use_rich: bool = True) -> None:
        self.min_rank = SEVERITY_ORDER.get(min_severity, 1)
        self.console = None
        if use_rich:
            try:
                from rich.console import Console
                self.console = Console()
            except ImportError:
                pass

    def write(self, alert: Alert) -> None:
        if SEVERITY_ORDER.get(alert.severity, 0) < self.min_rank:
            return
        stamp = alert.ts[11:23]
        if self.console:
            style = SEVERITY_STYLE.get(alert.severity, "white")
            self.console.print(
                f"[dim]{stamp}[/dim] "
                f"[{style}]{alert.severity.upper():<8}[/{style}] "
                f"[bold]{alert.name}[/bold] "
                f"[dim]sid:{alert.sid}[/dim] "
                f"{alert.flow} "
                f"[dim]{alert.detail}[/dim]",
                highlight=False,
            )
        else:
            print(f"{stamp} {alert.severity.upper():<8} {alert.name} "
                  f"sid:{alert.sid} {alert.flow} {alert.detail}")
