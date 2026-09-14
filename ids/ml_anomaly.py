"""Unsupervised ML anomaly detection for network traffic.

Learns a baseline of normal per-source behaviour from a benign capture using an
Isolation Forest, then flags source/time-window feature vectors that deviate from
it. Complements the signature/heuristic engine: it can surface novel or
slow-and-low activity that no hand-written rule anticipates.

    python -m ids.ml_anomaly train -b logs/benign_baseline.pcap -m models/if.joblib
    python -m ids.ml_anomaly score -m models/if.joblib -r logs/attack_sim.pcap

Feature vector per (source IP, time window):
    pkts, distinct_dst_ports, distinct_dst_ips, syn_count, syn_ratio,
    mean_size, distinct_flag_combos, total_bytes
"""
from __future__ import annotations
import argparse, math
from collections import defaultdict
from pathlib import Path

FEATURES = ["pkts", "distinct_dports", "distinct_dst", "syn", "syn_ratio",
            "mean_size", "distinct_flags", "bytes"]

def extract(pcap_path, window=5.0):
    """Return (rows, keys): feature rows and their (src_ip, window) keys."""
    from scapy.utils import rdpcap
    from scapy.layers.inet import IP, TCP
    buckets = defaultdict(lambda: {"pkts": 0, "dports": set(), "dst": set(),
                                   "syn": 0, "sizes": 0, "flags": set(), "bytes": 0})
    pkts = rdpcap(str(pcap_path))
    t0 = None
    for p in pkts:
        if IP not in p:
            continue
        ts = float(getattr(p, "time", 0) or 0)
        if t0 is None:
            t0 = ts
        ip = p[IP]
        key = (ip.src, int((ts - t0) // window))
        b = buckets[key]
        b["pkts"] += 1
        b["dst"].add(ip.dst)
        b["bytes"] += len(p)
        b["sizes"] += len(p)
        if TCP in p:
            tcp = p[TCP]
            b["dports"].add(int(tcp.dport))
            b["flags"].add(int(tcp.flags))
            if tcp.flags & 0x02:               # SYN
                b["syn"] += 1
    rows, keys = [], []
    for key, b in buckets.items():
        n = b["pkts"]
        rows.append([n, len(b["dports"]), len(b["dst"]), b["syn"],
                     b["syn"] / n if n else 0.0, b["sizes"] / n if n else 0.0,
                     len(b["flags"]), b["bytes"]])
        keys.append(key)
    return rows, keys

def train(baseline_pcap, model_path, window=5.0, contamination=0.02):
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np, joblib
    rows, _ = extract(baseline_pcap, window)
    if len(rows) < 3:
        raise SystemExit(f"baseline too small ({len(rows)} windows) — capture more benign traffic")
    X = np.array(rows, dtype=float)
    scaler = StandardScaler().fit(X)
    model = IsolationForest(n_estimators=200, contamination=contamination,
                            random_state=42).fit(scaler.transform(X))
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler, "window": window}, model_path)
    print(f"trained on {len(rows)} benign windows from {baseline_pcap} -> {model_path}")
    return model_path

def score(model_path, pcap, top=None):
    import numpy as np, joblib
    bundle = joblib.load(model_path)
    model, scaler, window = bundle["model"], bundle["scaler"], bundle["window"]
    rows, keys = extract(pcap, window)
    if not rows:
        print("no IP traffic to score"); return []
    X = scaler.transform(np.array(rows, dtype=float))
    raw = model.score_samples(X)            # higher = more normal
    preds = model.predict(X)                # -1 = anomaly
    results = []
    for key, row, s, pred in zip(keys, rows, raw, preds):
        results.append({"src_ip": key[0], "window": key[1],
                        "anomaly": pred == -1, "score": float(-s),  # higher = more anomalous
                        "features": dict(zip(FEATURES, row))})
    results.sort(key=lambda r: r["score"], reverse=True)
    anoms = [r for r in results if r["anomaly"]]
    print(f"scored {len(rows)} windows from {pcap}; {len(anoms)} anomalous\n")
    for r in (anoms if top is None else anoms[:top]):
        f = r["features"]
        print(f"  ANOMALY src={r['src_ip']:<15} score={r['score']:.2f}  "
              f"pkts={int(f['pkts'])} dports={int(f['distinct_dports'])} "
              f"syn_ratio={f['syn_ratio']:.2f} dst={int(f['distinct_dst'])}")
    return anoms

def main(argv=None):
    ap = argparse.ArgumentParser(description="ML traffic anomaly detector (Isolation Forest)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("train"); t.add_argument("-b", "--baseline", required=True)
    t.add_argument("-m", "--model", default="models/if.joblib")
    t.add_argument("-w", "--window", type=float, default=5.0)
    s = sub.add_parser("score"); s.add_argument("-m", "--model", default="models/if.joblib")
    s.add_argument("-r", "--read", required=True); s.add_argument("--top", type=int)
    a = ap.parse_args(argv)
    if a.cmd == "train":
        train(a.baseline, a.model, a.window)
    else:
        score(a.model, a.read, a.top)

if __name__ == "__main__":
    main()
