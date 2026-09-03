# Lab runbook — step by step

## 0. One-time host setup
```bash
cd ~/ids-lab
make setup
make test        # expect: 13 passed
make replay      # expect: 20 alerts, benign silent
```

## 1. Boot Kali
VirtualBox VM `KaliLinux2024` is bridged to en0, so it gets a 192.168.0.x address.
```bash
# in Kali:
ip a                      # note Kali's IP
ping -c1 192.168.0.166    # confirm it can reach the Mac
```
Copy the attack script into Kali (shared folder, scp, or paste):
```bash
scp ~/ids-lab/scripts/kali_attacks.sh kali@<KALI_IP>:~/
```

## 2. Start the IDS (Mac, terminal 1)
```bash
sudo .venv/bin/python -m ids.sensor -i en0 -f "host <KALI_IP>" --min-severity low
```
Leave it running. Alerts will stream here.

## 3. Attack (Kali, terminal 2)
```bash
chmod +x kali_attacks.sh
./kali_attacks.sh 192.168.0.166 portscan   # -> TCP Port Scan alert
./kali_attacks.sh 192.168.0.166 stealth    # -> NULL/FIN/XMAS alerts
./kali_attacks.sh 192.168.0.166 sweep      # -> Host Sweep alert
./kali_attacks.sh 192.168.0.166 web        # -> SQLi/XSS/traversal/log4shell/sqlmap/nikto
./kali_attacks.sh 192.168.0.166 brute      # -> SSH Brute Force alert
./kali_attacks.sh 192.168.0.166 synflood   # -> SYN Flood (critical)
./kali_attacks.sh 192.168.0.166 all        # everything
```

## 4. Review
```bash
# Mac: Ctrl-C the sensor to print the run summary, then:
cat logs/summary.json
jq -r '"\(.severity)\t\(.name)\t\(.src_ip) -> \(.dst_ip):\(.dst_port)"' logs/alerts.jsonl
```

## Troubleshooting
- **No packets seen**: confirm bridged adapter (not NAT); `en0` is the active Wi-Fi
  interface (`ifconfig en0`). If on Ethernet, use that interface instead.
- **Permission denied**: live capture needs `sudo`.
- **hydra/hping3/nikto missing in Kali**: `sudo apt update && sudo apt install -y hydra hping3 nikto`.
- **Firewall drops probes before the IDS host app answers**: detection still works —
  the IDS is passive and sees packets on the wire regardless of whether a service replies.
