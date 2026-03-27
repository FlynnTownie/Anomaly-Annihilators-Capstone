#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Predict from PCAP by extracting 6 features per flow and scoring them.

Priority:
  1) Score via the running Flask API (same endpoint the device_simulator uses)
  2) Fallback to a local IsolationForest model if --model is provided and API is down

Thresholding:
  - We decide severity from the API's (or local model's) raw score where
    more negative = more anomalous.
  - Only strong anomalies (score_raw <= --hi-thresh) are marked is_outlier:true + HIGH.
  - Borderline anomalies (<= --med-thresh) are MEDIUM (is_outlier:false).
  - Everything else is LOW.

This keeps batch output aligned with how your simulator looks, without flooding with HIGHs.
"""

import argparse, json, os, sys, time
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Dict, Tuple

# --- network parsing
from scapy.all import PcapReader, IP, IPv6, TCP, UDP

# --- http client for API scoring
import requests

# --- local model fallback (optional)
try:
    import numpy as np
    import joblib
except Exception:
    np = None
    joblib = None

FEATURE_KEYS = ["duration","orig_bytes","resp_bytes","pkts","proto_TCP","proto_UDP"]

# ---------- helpers ----------
def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return int(default)

def build_features(flow: Dict) -> Dict:
    """Map a flow dict into the 6 features expected by the API/model."""
    duration = max(0.0, float(flow["t_last"] - flow["t_first"]))
    orig_bytes = float(flow["orig_bytes"])
    resp_bytes = float(flow["resp_bytes"])
    pkts = int(flow["pkts"])
    proto_tcp = 1 if flow["proto"] == "tcp" else 0
    proto_udp = 1 if flow["proto"] == "udp" else 0
    return {
        "duration": round(duration, 3),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "pkts": pkts,
        "proto_TCP": proto_tcp,
        "proto_UDP": proto_udp,
    }

def canonical_key(src: str, sport: int, dst: str, dport: int, proto: str) -> Tuple[Tuple[str,str,str], bool]:
    """Bidirectional 5-tuple key so we aggregate both directions into one flow."""
    a = f"{src}:{sport}"
    b = f"{dst}:{dport}"
    if a <= b:
        return (a, b, proto), True   # packet direction matches (a -> b)
    else:
        return (b, a, proto), False  # packet is reverse (b <- a)

def extract_flows_from_pcap(pcap_path: Path) -> List[Dict]:
    """
    Read PCAP and aggregate into Zeek-like bidirectional flows with:
      src, dst, sport, dport, proto, t_first, t_last, orig_bytes, resp_bytes, pkts
    """
    flows: Dict[Tuple[str,str,str], Dict] = {}
    counts = defaultdict(int)

    with PcapReader(str(pcap_path)) as pr:
        for pkt in pr:
            try:
                ts = float(pkt.time)
            except Exception:
                ts = time.time()

            ip = None
            if IP in pkt:
                ip = pkt[IP]
                src, dst = ip.src, ip.dst
                ip_len = int(getattr(ip, "len", len(bytes(ip))))
            elif IPv6 in pkt:
                ip = pkt[IPv6]
                src, dst = ip.src, ip.dst
                ip_len = len(bytes(ip))
            else:
                continue  # non-IP

            if TCP in pkt:
                proto = "tcp"
                sport = safe_int(pkt[TCP].sport)
                dport = safe_int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "udp"
                sport = safe_int(pkt[UDP].sport)
                dport = safe_int(pkt[UDP].dport)
            else:
                continue

            key, fwd = canonical_key(src, sport, dst, dport, proto)
            if key not in flows:
                a, b, p = key
                src_a, sport_a = a.rsplit(":", 1)
                dst_b, dport_b = b.rsplit(":", 1)
                flows[key] = {
                    "src": src_a, "sport": int(sport_a),
                    "dst": dst_b, "dport": int(dport_b),
                    "proto": p,
                    "t_first": ts, "t_last": ts,
                    "orig_bytes": 0.0, "resp_bytes": 0.0,
                    "pkts": 0,
                }

            fl = flows[key]
            fl["t_last"] = max(fl["t_last"], ts)
            fl["pkts"] += 1
            if fwd:
                fl["orig_bytes"] += ip_len
            else:
                fl["resp_bytes"] += ip_len

            counts["pkts_total"] += 1

    return list(flows.values())

# ---------- API helpers ----------
def post_to_api(api_url: str, feature_dicts: List[Dict]) -> List[Dict]:
    """
    Call the same /predict endpoint the device_simulator uses.
    Accepts a list of feature dicts and returns the API's list of results.
    """
    results: List[Dict] = []
    for i in range(0, len(feature_dicts), 200):
        chunk = feature_dicts[i:i+200]
        r = requests.post(api_url, json=chunk, timeout=10)
        r.raise_for_status()
        res = r.json()
        if isinstance(res, dict):
            res = [res]
        results.extend(res)
    return results

def detect_api_url(cli_api: str | None) -> str:
    """Pick API URL: CLI --api > $API_URL > default."""
    return (cli_api or os.getenv("API_URL") or "http://127.0.0.1:8000/predict").rstrip("/")

def api_is_up(health_base: str) -> bool:
    """Quick /health probe; health_base should be http://host:port"""
    health = health_base.rstrip("/") + "/health"
    try:
        r = requests.get(health, timeout=1.5)
        return r.ok
    except Exception:
        return False

# ---------- Local model fallback ----------
def load_local_model(model_path: Path):
    if joblib is None:
        raise RuntimeError("joblib / numpy not available for local scoring.")
    return joblib.load(str(model_path))

def score_local_model(iso, feature_rows: List[Dict]) -> List[Dict]:
    """Mimic the API response shape using a local IsolationForest."""
    X = np.array([[row[k] for k in FEATURE_KEYS] for row in feature_rows], dtype=float)
    # sklearn iforest: decision_function > 0 => inlier; < 0 => outlier
    dfn = iso.decision_function(X)  # shape (n,)
    preds = iso.predict(X)          # +1 inlier, -1 outlier
    results = []
    for df_i, pred in zip(dfn, preds):
        raw = float(df_i)                # negative = anomalous (aligns with API "score_raw")
        score = max(0.0, -raw)           # positive magnitude for anomalies
        is_out = bool(pred == -1)
        results.append({
            "is_outlier": is_out,
            "score_raw": raw,
            "score": score,
            "model": "local_isolation_forest.pkl",
            "source": "local",
            "severity": "HIGH" if is_out else "LOW",
            "severity_rule": "isolation_forest.predict -> -1 => HIGH, else LOW",
        })
    return results

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="pcap file to score")
    ap.add_argument("--model", required=False, help="local model path (fallback if API is down)")
    ap.add_argument("--out",   required=True, help="ndjson output file")
    ap.add_argument("--api",   required=False, help="override API endpoint, e.g. http://127.0.0.1:8000/predict")

    # Thresholds: only <= hi-thresh becomes is_outlier:true + HIGH
    ap.add_argument("--hi-thresh", type=float, default=-0.12,
                    help="score_raw <= this => HIGH & is_outlier=true (default: -0.12)")
    ap.add_argument("--med-thresh", type=float, default=-0.05,
                    help="score_raw <= this => MEDIUM (default: -0.05)")

    args = ap.parse_args()

    pcap_path = Path(args.pcap).expanduser().resolve()
    out_path  = Path(args.out).expanduser().resolve()
    model_path = Path(args.model).expanduser().resolve() if args.model else None

    print(f"📦 PCAP: {pcap_path}")
    print(f"📄 OUT : {out_path}")
    if model_path:
        print(f"🧠 MODEL (fallback): {model_path}")

    if not pcap_path.exists():
        print(f"❌ PCAP not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    # 1) Extract flows
    flows = extract_flows_from_pcap(pcap_path)
    print(f"🔎 extracted {len(flows)} flows")

    # Always write the file (even if empty) so pipelines don't break
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not flows:
        out_path.write_text("")
        print(f"ℹ️ No flows; wrote empty {out_path}")
        return

    # 2) Build features for scoring
    feature_rows = [build_features(f) for f in flows]

    # 3) Choose scoring route
    api_url = detect_api_url(args.api)
    api_base = api_url.split("/predict")[0] if "/predict" in api_url else api_url.rsplit("/", 1)[0]

    use_api = api_is_up(api_base)
    results = None
    route = None

    if use_api:
        print(f"🌐 scoring via API: {api_url}")
        try:
            results = post_to_api(api_url, feature_rows)
            route = "api"
        except Exception as e:
            print(f"⚠️ API error: {e}.", file=sys.stderr)
            use_api = False

    if not use_api:
        if model_path and model_path.exists():
            if joblib is None:
                print("❌ API down and local scoring unavailable (joblib/numpy missing).", file=sys.stderr)
                sys.exit(1)
            print(f"🧪 scoring via LOCAL model: {model_path}")
            iso = load_local_model(model_path)
            results = score_local_model(iso, feature_rows)
            route = "local"
        else:
            print("❌ API not reachable and no valid --model provided for fallback.", file=sys.stderr)
            print("   Start model_api.py (or run via your run_all script), or pass --api URL / --model path.", file=sys.stderr)
            sys.exit(1)

    if len(results) != len(flows):
        print(f"⚠️ Got {len(results)} results for {len(flows)} flows; aligning by index.", file=sys.stderr)

    # 4) Write NDJSON combining flow metadata + thresholded decision
    now_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    outliers = 0
    sev_rule = f"<= {args.hi_thresh} -> HIGH; <= {args.med_thresh} -> MED; else LOW"

    with out_path.open("w") as w:
        for i, f in enumerate(flows):
            res = results[i] if i < len(results) else {}

            # pull raw score (negative = more anomalous)
            raw = float(res.get("score_raw", 0.0))
            score = float(res.get("score", max(0.0, -raw)))

            # Thresholding for presentation
            if raw <= args.hi_thresh:
                sev = "HIGH"
                is_out = True
            elif raw <= args.med_thresh:
                sev = "MEDIUM"
                is_out = False
            else:
                sev = "LOW"
                is_out = False

            if is_out:
                outliers += 1

            doc = {
                "ts": now_ts,
                # Flow identifiers
                "src": f["src"], "dst": f["dst"],
                "sport": f["sport"], "dport": f["dport"],
                "proto": f["proto"],
                # Features (useful for Kibana)
                **build_features(f),
                # Model/API outputs (aligned with simulator)
                "is_outlier": is_out,
                "score_decision": 1 if is_out else 0,
                "severity": sev,
                "score_raw": raw,
                "score": score,
                "model": res.get("model", "isolation_forest.joblib" if route == "api" else "local_isolation_forest.pkl"),
                "source": "batch-api" if route == "api" else "batch-local",
                "severity_rule": sev_rule,
            }
            w.write(json.dumps(doc) + "\n")

    print(f"✅ wrote {len(flows)} records to {out_path}  (outliers={outliers})")

if __name__ == "__main__":
    main()
