#!/usr/bin/env python3
"""
Capture a short PCAP (needs root), run the predictor, and optionally ship detections to Elasticsearch.
If you don't pass --elastic-url and --api-key, it will just write NDJSON to detections/.

Examples:
  # macOS test (usually en0)
  sudo python run_all_fixed.py --iface en0 --seconds 10 --model models/iso6.pkl

  # Raspberry Pi (usually wlan0 or eth0)
  sudo python run_all_fixed.py --iface wlan0 --seconds 20 --model models/iso6.pkl \
    --elastic-url http://<ES_HOST>:9200 --index anomalies-capstone --api-key <API_KEY>
"""
import argparse, datetime as dt, os, sys, subprocess, shlex, json, tempfile, time
from pathlib import Path

def ensure_root_or_reexec():
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("🔐 Elevating with sudo for tcpdump capture...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

def run(cmd, cwd=None):
    print(f"▶ {cmd if isinstance(cmd,str) else ' '.join(cmd)}")
    return subprocess.run(cmd if isinstance(cmd,list) else shlex.split(cmd), cwd=cwd, check=True)

def newest_ndjson(path: Path):
    files = sorted(path.glob("out_*.ndjson"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        files = sorted(path.glob("*.ndjson"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", default=os.getenv("IFACE", "wlan0"))
    p.add_argument("--seconds", type=int, default=int(os.getenv("CAPTURE_SECONDS", "20")))
    p.add_argument("--model", default=os.getenv("MODEL_PATH", "models/iso6.pkl"))
    p.add_argument("--elastic-url", default=os.getenv("ELASTIC_URL"))
    p.add_argument("--index", default=os.getenv("INDEX_NAME", "anomalies-capstone"))
    p.add_argument("--api-key", default=os.getenv("ELASTIC_API_KEY"))
    p.add_argument("--pcap-dir", default=".")
    p.add_argument("--detections-dir", default="detections")
    args = p.parse_args()

    repo = Path(__file__).resolve().parent
    pcap_dir = (repo / args.pcap_dir); pcap_dir.mkdir(parents=True, exist_ok=True)
    det_dir  = (repo / args.detections_dir); det_dir.mkdir(parents=True, exist_ok=True)

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pcap_path = pcap_dir / f"traffic_{args.iface}_{stamp}.pcap"
    out_path = det_dir / f"out_{stamp}.ndjson"
    out_path = det_dir / f"out_{stamp}.ndjson"

    ensure_root_or_reexec()
    print(f"🌐 Capturing {args.seconds}s on {args.iface} -> {pcap_path}")
    # Cross-platform: start tcpdump, sleep N seconds, then terminate
    print("⏱ Starting tcpdump…")
    proc = subprocess.Popen(["tcpdump", "-i", args.iface, "-w", str(pcap_path)])
    try:
        time.sleep(args.seconds)
    finally:
        print("⏹ Stopping tcpdump…")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

    model_path = repo / args.model
    if not model_path.exists():
        print(f"❌ Model not found: {model_path}", file=sys.stderr); sys.exit(2)

    venv_py = repo / ".venv" / "bin" / "python"
    py = str(venv_py) if venv_py.exists() else sys.executable

    print("🧠 Scoring PCAP with Isolation Forest…")
    run([py, "predict_from_pcap.py", "--pcap", str(pcap_path), "--model", str(model_path), "--out", str(out_path)])

    nd = newest_ndjson(det_dir)
    if not nd:
        print("⚠ No detections NDJSON found in detections/."); sys.exit(0)
    print(f"✅ Detections at: {nd}")

    if args.elastic_url and args.api_key:
        print(f"🚚 Shipping to {args.elastic_url} index={args.index}")
        action = {"index": {"_index": args.index}}
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            with open(nd) as src:
                for line in src:
                    line=line.strip()
                    if not line: continue
                    tmp.write(json.dumps(action)+"\n"); tmp.write(line+"\n")
            bulk_file = tmp.name
        run(["curl","-sS","-XPOST",f"{args.elastic_url.rstrip('/')}/_bulk",
             "-H","Content-Type: application/x-ndjson",
             "-H",f"Authorization: ApiKey {args.api_key}",
             "--data-binary", f"@{bulk_file}"])
        print("🎉 Shipped to Elasticsearch.")
    else:
        print("ℹ Skipping ship step (no --elastic-url or --api-key).")
    print("🏁 Done.")
if __name__ == "__main__":
    main()
