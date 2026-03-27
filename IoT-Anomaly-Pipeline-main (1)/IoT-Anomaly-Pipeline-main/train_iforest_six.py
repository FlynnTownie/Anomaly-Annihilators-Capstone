import argparse, os
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

def make_features(df: pd.DataFrame) -> pd.DataFrame:
    # --- numeric columns: coerce or create zeros ---
    for col in ["duration", "orig_bytes", "resp_bytes"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
        else:
            df[col] = pd.Series(0.0, index=df.index)

    # --- total packets ---
    if {"orig_pkts", "resp_pkts"}.issubset(df.columns):
        df["orig_pkts"] = pd.to_numeric(df["orig_pkts"], errors="coerce").fillna(0).astype(int)
        df["resp_pkts"] = pd.to_numeric(df["resp_pkts"], errors="coerce").fillna(0).astype(int)
        df["pkts"] = (df["orig_pkts"] + df["resp_pkts"]).astype(int)
    else:
        df["pkts"] = 1

    # --- protocol one-hots ---
    if "proto" in df.columns:
        proto = df["proto"].astype(str).str.lower()
    else:
        proto = pd.Series("", index=df.index)
    df["proto_TCP"] = (proto == "tcp").astype(int)
    df["proto_UDP"] = (proto == "udp").astype(int)

    # return features in the exact order your scorer expects
    return df[["duration","orig_bytes","resp_bytes","pkts","proto_TCP","proto_UDP"]].copy()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Path to dataset (Zeek conn.log or CSV)")
    ap.add_argument("--save", default="models/iso6.pkl", help="Where to save the model")
    ap.add_argument("--contam", type=float, default=0.1, help="IsolationForest contamination")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.save) or ".", exist_ok=True)

    # smart loader: supports Zeek .log/.labeled/.tsv
    path = args.data
    if path.endswith((".log", ".tsv", ".labeled")):
        df = pd.read_csv(path, sep=r"\s+|\t", engine="python",
                         comment="#", na_values=["-","(empty)"])
    elif path.endswith((".gz", ".zip")):
        df = pd.read_csv(path, compression="infer")
    else:
        df = pd.read_csv(path)

    X = make_features(df)

    iso = IsolationForest(
        n_estimators=300,
        max_samples="auto",
        contamination=args.contam,
        random_state=42,
        n_jobs=-1
    ).fit(X)

    joblib.dump(iso, args.save)
    print(f"✅ Saved model to {args.save}")
    print("Feature order:", ["duration","orig_bytes","resp_bytes","pkts","proto_TCP","proto_UDP"])

if __name__ == "__main__":
    main()
