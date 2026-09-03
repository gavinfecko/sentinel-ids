# Lab runbook — end to end

## Phase 0 — host setup (done)
```bash
cd ~/ids-lab
make setup      # venv + scapy/pyyaml/rich
make test       # 13 passing
make demo       # replay attack sim -> logs/report.html  (no root, no VM)
```

## Phase 1 — get the Kali VM
The Kali 2026.2 prebuilt VirtualBox image (amd64) downloads to `~/kali-vm/`.
When it finishes and the checksum verifies, import + configure it:

```bash
bash ~/kali-vm/setup_kali_vm.sh
```
This extracts the image, registers the VM, and sets the network adapter to
**Bridged on en0** with 4 GB RAM / 2 CPUs.

**If a command is blocked** (VirtualBox management can be restricted), do it once in
the VirtualBox GUI instead:
1. Extract: `cd ~/kali-vm && 7zz x kali-linux-2026.2-virtualbox-amd64.7z`
2. VirtualBox → **Tools → Add** → pick the extracted `.vbox` file.
3. Select the VM → **Settings → Network → Adapter 1** → *Attached to:* **Bridged Adapter**,
   *Name:* **en0**. OK.
4. **Start**. Login: `kali` / `kali`.

## Phase 2 — confirm the network
In Kali:
```bash
ip -4 addr show eth0        # expect an address on 192.168.0.x
ping -c1 192.168.0.166      # reach the macOS IDS host
```
If Kali gets a 10.x/NAT address instead, the adapter is still on NAT — set it to
Bridged (Phase 1, step 3) and reboot the VM.

## Phase 3 — run the lab
**macOS host, terminal 1** — start the sensor (root needed for capture):
```bash
cd ~/ids-lab
sudo .venv/bin/python -m ids.dashboard -i en0 --config config/sentinel.yaml \
     -f "host <KALI_IP>"
```

**Kali, terminal 2** — copy the playbook in, then attack:
```bash
scp ~/ids-lab/scripts/kali_attacks.sh kali@<KALI_IP>:~/   # or share via folder
chmod +x kali_attacks.sh
./kali_attacks.sh 192.168.0.166 portscan   # -> TCP Port Scan
./kali_attacks.sh 192.168.0.166 stealth    # -> NULL/FIN/XMAS
./kali_attacks.sh 192.168.0.166 sweep      # -> Host Sweep
./kali_attacks.sh 192.168.0.166 web        # -> SQLi/XSS/traversal/log4shell/sqlmap/nikto
./kali_attacks.sh 192.168.0.166 brute      # -> SSH Brute Force
./kali_attacks.sh 192.168.0.166 synflood   # -> SYN Flood (critical)
./kali_attacks.sh 192.168.0.166 all        # everything
```
Missing tools in Kali: `sudo apt update && sudo apt install -y hydra hping3 nikto`.

## Phase 4 — report
```bash
# macOS: Ctrl-C the sensor, then
.venv/bin/python -m ids.report -o logs/report.html -t "Kali Lab — Live Run"
open logs/report.html
jq -r '"\(.severity)\t\(.name)\t\(.src_ip)->\(.dst_ip):\(.dst_port)\t\(.mitre)"' logs/alerts.jsonl
```

## Troubleshooting
- **No packets**: confirm the adapter is Bridged (not NAT), and that `en0` is the active
  interface (`ifconfig en0` shows the 192.168.0.166 address). On Ethernet, use that iface.
- **Permission denied on capture**: live sniff needs `sudo`.
- **Firewall drops probes**: detection still works — the IDS is passive and reads packets
  off the wire whether or not a local service answers.
