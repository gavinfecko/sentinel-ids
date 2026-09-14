"""Real-time alert notifications: fire on high-severity alerts through any of
several channels, implemented as an AlertBus sink with no third-party deps
(stdlib urllib + osascript only).

Channels (all optional, config-driven):
  - desktop : macOS Notification Center banner (local demo)
  - ntfy    : push to your phone via ntfy.sh — free, no account, just a topic
  - webhook : Slack / Discord incoming webhook ({"text": ...})
  - resend  : email via the Resend API (needs api key + verified from-address)

Config (sentinel.yaml):
    notify:
      enabled: true
      min_severity: critical        # info|low|medium|high|critical
      cooldown: 30                  # seconds between repeats of the same signature
      desktop: true
      ntfy_topic: "gavin-ids-7f3a"  # -> https://ntfy.sh/<topic>  (pick something unguessable)
      ntfy_server: "https://ntfy.sh"
      webhook_url: ""               # Slack/Discord
      resend: {api_key: "", from: "", to: ""}
"""
from __future__ import annotations
import json, subprocess, sys, time, urllib.request

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# ntfy priority + tag emoji per severity
_NTFY = {"critical": ("5", "rotating_light"), "high": ("4", "warning"),
         "medium": ("3", "eyes"), "low": ("2", "mag"), "info": ("1", "information_source")}

class NotifySink:
    def __init__(self, min_severity="critical", cooldown=30.0, desktop=True,
                 ntfy_topic="", ntfy_server="https://ntfy.sh", webhook_url="",
                 resend=None):
        self.min_rank = _RANK.get(min_severity, 4)
        self.cooldown = float(cooldown)
        self.desktop = desktop
        self.ntfy_topic = ntfy_topic or ""
        self.ntfy_server = (ntfy_server or "https://ntfy.sh").rstrip("/")
        self.webhook_url = webhook_url or ""
        self.resend = resend or {}
        self._last: dict[int, float] = {}
        self.sent = 0

    def _ready(self, sid, now):
        last = self._last.get(sid)
        if last is not None and now - last < self.cooldown:
            return False
        self._last[sid] = now
        return True

    def format(self, alert):
        who = f"{alert.src_ip or '?'} -> {alert.dst_ip or '?'}"
        port = f":{alert.dst_port}" if alert.dst_port else ""
        return (f"[{alert.severity.upper()}] {alert.name}",
                f"{who}{port}  ({alert.mitre or 'n/a'})  {alert.detail[:140]}")

    def _post(self, url, data, headers, timeout=5, label="notify"):
        try:
            urllib.request.urlopen(
                urllib.request.Request(url, data=data, headers=headers), timeout=timeout)
        except Exception as exc:
            print(f"[{label}] failed: {type(exc).__name__}: {exc}")

    def _desktop(self, title, body):
        if not (self.desktop and sys.platform == "darwin"):
            return
        safe = lambda s: s.replace('"', "'").replace("\\", "")
        self._run(["osascript", "-e", f'display notification "{safe(body)}" with title "{safe(title)}"'])

    @staticmethod
    def _run(cmd):
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _ntfy(self, alert, title, body):
        if not self.ntfy_topic:
            return
        prio, tag = _NTFY.get(alert.severity, ("3", "warning"))
        self._post(f"{self.ntfy_server}/{self.ntfy_topic}", body.encode("utf-8"),
                   {"Title": title, "Priority": prio, "Tags": tag}, label="ntfy")

    def _webhook(self, title, body):
        if not self.webhook_url:
            return
        self._post(self.webhook_url, json.dumps({"text": f"*{title}*\n{body}"}).encode(),
                   {"Content-Type": "application/json"}, label="webhook")

    def _resend(self, title, body):
        r = self.resend
        if not (r.get("api_key") and r.get("from") and r.get("to")):
            return
        payload = json.dumps({"from": r["from"], "to": [r["to"]],
                              "subject": title, "text": body}).encode()
        self._post("https://api.resend.com/emails", payload,
                   {"Content-Type": "application/json",
                    "Authorization": f"Bearer {r['api_key']}"}, label="resend")

    def write(self, alert):
        if _RANK.get(alert.severity, 0) < self.min_rank:
            return
        if not self._ready(alert.sid, time.time()):
            return
        title, body = self.format(alert)
        self._desktop(title, body)
        self._ntfy(alert, title, body)
        self._webhook(title, body)
        self._resend(title, body)
        self.sent += 1

def from_config(cfg):
    n = (cfg or {}).get("notify", {})
    if not n.get("enabled"):
        return None
    return NotifySink(min_severity=n.get("min_severity", "critical"),
                      cooldown=n.get("cooldown", 30), desktop=n.get("desktop", True),
                      ntfy_topic=n.get("ntfy_topic", ""),
                      ntfy_server=n.get("ntfy_server", "https://ntfy.sh"),
                      webhook_url=n.get("webhook_url", ""), resend=n.get("resend"))
