import joblib, numpy as np, json, requests

class ModelClient:
    def __init__(self, cfg):
        self.mode = cfg["model"]["mode"]
        with open(cfg["features"]["schema_path"]) as f:
            self.schema = json.load(f)["order"]
        if self.mode == "local":
            self.model = joblib.load(cfg["model"]["local_model_path"])
        else:
            self.api_url = cfg["model"]["api_url"]

    def _vec(self, feats: dict):
        return np.array([[feats.get(k, 0.0) for k in self.schema]], dtype=float)

    def infer(self, features: dict):
        X = self._vec(features)
        if self.mode == "local":
            is_outlier = int(self.model.predict(X)[0] == -1)
            score_raw = -float(self.model.score_samples(X)[0])  # higher = more anomalous
            score = 1 / (1 + np.exp(-score_raw))
            return float(score), bool(is_outlier)
        else:
            r = requests.post(self.api_url, json={"features": features})
            r.raise_for_status()
            d = r.json()
            return float(d["score"]), bool(d["is_outlier"])
