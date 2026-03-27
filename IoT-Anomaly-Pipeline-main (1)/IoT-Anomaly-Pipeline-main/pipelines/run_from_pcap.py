import argparse, json, sys
from collections import defaultdict
from pathlib import Path
import requests
from scapy.all import rdpcap, TCP, UDP, IP

SCHEMA = ["duration","orig_bytes","resp_bytes","pkts","proto_TCP","proto_UDP"]

def flows_from_pcap(pcap_path):
    packets = rdpcap(str(pcap_path))
    flows = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        else:
            # skip non TCP/UDP
            continue

        key = (ip.src, sport, ip.dst, dport, proto)
        rkey = (ip.dst, dport, ip.src, sport, proto)
        plen = int(len(bytes(pkt)))
        ts = float(pkt.time)

        if key in flows:
            f = flows[key]
            f["end"] = ts
            f["pkts"] += 1
            f["orig_bytes"] += plen
        elif rkey in flows:
            f = flows[rkey]
            f["end"] = ts
            f["pkts"] += 1
            f["resp_bytes"] += plen
        else:
            flows[key] = {
                "start": ts,
                "end": ts,
                "pkts": 1,
                "orig_bytes": plen,
                "resp_bytes": 0,
                "proto": proto,
                "id": f"{ip.src}:{sport}->{ip.dst}:{dport}/{proto}",
            }
    return list(flows.values())

def to_features(flow):
    dur = max(0.0, float(flow["end"] - flow["start"]))
    f = {
        "duration": float(dur),
        "orig_bytes": int(flow["orig_bytes"]),
        "resp_bytes": int(flow["resp_bytes"]),
        "pkts": int(flow["pkts"]),
        "proto_TCP": 1 if flow["proto"] == "TCP" else 0,
        "proto_UDP": 1 if flow["proto"] == "UDP" else 0,
    }
    for k in SCHEMA:
        f.setdefault(k, 0 if k != "duration" else 0.0)
    return f

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="Path to pcap")
    ap.add_argument("--api", default="http://192.168.4.164:5050/predict", help="Model API URL")
    ap.add_argument("--out", default="detections/out.jsonl", help="Output JSONL file")
    args = ap.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        print(f"[!] pcap not found: {pcap}", file=sys.stderr); sys.exit(1)

    flows = flows_from_pcap(pcap)
    if not flows:
        print("[!] No flows parsed."); sys.exit(1)

    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)

    counts = defaultdict(int)
    with out.open("w") as fh:
        for flow in flows:
            feats = to_features(flow)
            payload = {"features": feats}
            try:
                r = requests.post(args.api, json=payload, timeout=5)
                r.raise_for_status()
                resp = r.json()
            except Exception as e:
                resp = {"error": str(e)}

            rec = {
                "flow_id": flow["id"],
                "features": feats,
                "result": resp,
                "ts_start": flow["start"],
                "ts_end": flow["end"],
            }
            fh.write(json.dumps(rec) + "\n")

            sev = (resp.get("severity") or "ERROR") if isinstance(resp, dict) else "ERROR"
            counts[sev] += 1

    print(f"[OK] Processed {len(flows)} flows from {pcap}")
    for k in sorted(counts.keys()):
        print(f"  {k}: {counts[k]}")
    print(f"[→] Wrote: {out}")

if __name__ == "__main__":
    main()

