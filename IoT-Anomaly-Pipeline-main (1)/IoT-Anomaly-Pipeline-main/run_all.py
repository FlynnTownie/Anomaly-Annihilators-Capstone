import subprocess, time, os, platform
from datetime import datetime, timezone

API_PORT = 8000                 # your Flask showed 8000
PACKET_COUNT = "400"            # capture this many packets then stop
MAC_IFACE = "en0"               # typical Wi-Fi on macOS
PI_IFACE  = "wlan0"             # typical Wi-Fi on Raspberry Pi

def detect_iface():
    return MAC_IFACE if platform.system() == "Darwin" else PI_IFACE

iface = detect_iface()
stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
pcap_name = f"traffic_{iface}_{stamp}.pcap"
pcap_path = pcap_name  # keep as string for CLI calls

print("🚀 Starting everything...")

# 1) Start model API (pipe logs so errors are visible)
print("🧠 Starting model_api.py ...")
api_proc = subprocess.Popen(
    ["python3", "model_api.py"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)

# Wait up to ~12s for Flask to boot, printing logs
ready = False
for _ in range(12):
    line = api_proc.stdout.readline().strip()
    if line:
        print("[api]", line)
    try:
        import urllib.request
        urllib.request.urlopen(f"http://127.0.0.1:{API_PORT}/health", timeout=1).read()
        ready = True
        break
    except Exception:
        time.sleep(1)

if not ready:
    print("❌ API failed to start (no /health). See [api] logs above.")
    api_proc.terminate()
    raise SystemExit(1)
print(f"✅ API ready on http://127.0.0.1:{API_PORT}")

# 2) Start tcpdump (stop after PACKET_COUNT)
print(f"📡 Capturing {PACKET_COUNT} packets on {iface} -> {pcap_name}")
tcpdump_proc = subprocess.Popen(
    ["sudo", "tcpdump", "-i", iface, "-c", PACKET_COUNT, "-w", pcap_name],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)
# Show a few tcpdump lines so you see interface/perm errors
for _ in range(6):
    td = tcpdump_proc.stdout.readline().strip()
    if td:
        print("[tcpdump]", td)

# 3) Start device simulator pointed at the correct API
env = os.environ.copy()
env["API_URL"] = f"http://127.0.0.1:{API_PORT}/predict"
print(f"🤖 Starting device_simulator.py (API_URL={env['API_URL']}) ...")
sim_proc = subprocess.Popen(
    ["python3", "device_simulator.py"],
    env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)
# Print a couple of simulator lines so you know it’s posting
for _ in range(6):
    sline = sim_proc.stdout.readline().strip()
    if sline:
        print("[sim]", sline)

print("✅ Running. Auto-stops when tcpdump hits packet limit. (Ctrl+C to stop early.)")

try:
    tcpdump_proc.wait()  # wait until PACKET_COUNT captured
finally:
    print("\n🛑 Stopping simulator and API ...")
    sim_proc.terminate()
    api_proc.terminate()
    time.sleep(1)
    print(f"✅ Done. PCAP saved as {pcap_name}")
    try:
        sz = os.path.getsize(pcap_name)
        print(f"   File size: {sz} bytes")
    except FileNotFoundError:
        print("   ⚠️ PCAP not found. Check interface name and permissions.")
print("\n🧮 Running post-capture anomaly detection ...")
score_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def _run_cmd(cmd: str):
    import shlex, subprocess
    print(f"→ {cmd}")
    return subprocess.call(shlex.split(cmd))

cmd = (
    "python3 predict_from_pcap.py "
    f"--pcap {pcap_path} "
    "--model api "
    f"--out detections/out_{score_stamp}.ndjson"
)
rc = _run_cmd(cmd)
if rc != 0:
    print("❌ Post-capture detection failed.")
    raise SystemExit(rc)

from pathlib import Path as _P
out_guess = _P(f"detections/out_{score_stamp}.ndjson")
if out_guess.exists():
    print(f"📄 Detections written to {out_guess}")
else:
    print("ℹ️ Scoring finished, but output file not found — check your script’s --out path.")
print("🏁 All done.")
