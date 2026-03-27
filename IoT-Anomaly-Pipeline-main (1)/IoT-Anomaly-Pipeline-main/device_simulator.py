import time, random, requests, os
from dotenv import load_dotenv

# ES disabled by default; no hard import
DISABLE_ES = os.getenv("DISABLE_ES", "1") == "1"
try:
    from elasticsearch import Elasticsearch
except Exception:
    Elasticsearch = None
USE_ES = (not DISABLE_ES) and (Elasticsearch is not None)

load_dotenv()
API = os.getenv("API_URL", "http://127.0.0.1:8000/predict")
ANOMALY_RATE = float(os.getenv("ANOMALY_RATE", "0.35"))  # 0.35–0.6 is nice for demos

if USE_ES:
    ES_URL = os.getenv("ES_URL", "http://localhost:9200")
    ES_INDEX = os.getenv("ES_INDEX", "iot-alerts-sim")
    es = Elasticsearch(ES_URL)
    print(f"[ES] Connected to {ES_URL}, index={ES_INDEX}")
else:
    es = None

def normal_sample():
    return {
        "duration": round(random.uniform(0.003, 0.12), 3),
        "orig_bytes": random.choice([48, 64, 96, 128, 256]),
        "resp_bytes": random.choice([48, 64, 96, 256, 512, 1500, 3000]),
        "pkts": random.choices([1, 2, 3, 4, 5, 8, 12], weights=[25,30,20,10,8,4,3])[0],
        **({"proto_TCP": 0, "proto_UDP": 1} if random.random() < 0.85
           else {"proto_TCP": 1, "proto_UDP": 0})
    }

def c2_like_sample():
    return {
        "duration": round(random.uniform(0.5, 2.0), 3),
        "orig_bytes": random.randint(400, 1800),
        "resp_bytes": random.randint(5000, 150000),
        "pkts": random.randint(20, 80),
        "proto_TCP": 1,
        "proto_UDP": 0
    }

i = 0
print(f"[sim] Starting device simulator. Sending to API: {API}")
if not USE_ES:
    print("[sim] Elasticsearch output disabled (DISABLE_ES=1).")

while True:
    sample = c2_like_sample() if i % 8 == 0 else normal_sample()
    try:
        r = requests.post(API, json=sample, timeout=2)
        resp = r.json()
        print("sent:", sample, " got:", resp)

        if USE_ES and es:
            doc = {**sample, **resp}
            es.index(index=ES_INDEX, document=doc)

    except Exception as e:
        print("API not ready yet:", e)

    i += 1
    time.sleep(2)
