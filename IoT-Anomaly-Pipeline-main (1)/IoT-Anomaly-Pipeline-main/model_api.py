from flask import Flask, request, jsonify
import joblib, numpy as np, json, time

app = Flask(__name__)

# Load model + schema
MODEL = joblib.load("isolation_forest.joblib")
SCHEMA = json.load(open("config/feature_schema.json"))["order"]

def vec(feats):
    """Turn dict of features into numpy array (in schema order)."""
    return np.array([[feats.get(k, 0.0) for k in SCHEMA]], dtype=float)

def get_severity(score: float) -> str:
    """Map anomaly score to severity levels."""
    if score >= 0.8:
        return "HIGH"
    elif score >= 0.6:
        return "MEDIUM"
    elif score >= 0.4:
        return "LOW"
    else:
        return "NORMAL"

@app.route("/infer", methods=["POST"])
def infer():
    t0 = time.time()
    data = request.get_json(force=True)
    feats = data.get("features", data)
    X = vec(feats)

    # Run inference
    pred = MODEL.predict(X)[0]
    is_outlier = bool(pred == -1)
    score_raw = -float(MODEL.score_samples(X)[0])  # higher = more anomalous
    score = 1.0 / (1.0 + np.exp(-score_raw))

    return jsonify({
        "score": float(score),
        "is_outlier": is_outlier,
        "severity": get_severity(score),
        "latency_ms": int((time.time() - t0) * 1000)
    })

# --- added routes for simulator ---
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True}), 200

@app.route("/predict", methods=["POST"])
def predict():
    # Reuse the same logic as /infer
    return infer()
# --- end added routes ---

if __name__ == "__main__":
    # Run on 8000 (matches your current server)
    app.run(host="0.0.0.0", port=8000)
