# IoT Anomaly Pipeline

An end-to-end anomaly detection pipeline for IoT network traffic, built to identify Command & Control (C&C) communications and malicious flows using an Isolation Forest model trained on the [IoT-23 dataset](https://www.stratosphereips.org/datasets-iot23).

Developed as part of a university capstone project (UTS, Spring 2025).

---

## What It Does

1. **Ingests** network traffic — either live packet capture (pcap) or Zeek-format connection logs
2. **Extracts** flow-level features (bytes, packets, duration, protocol)
3. **Scores** each flow with a pre-trained Isolation Forest model via a REST API
4. **Classifies** detections by severity: `HIGH`, `MEDIUM`, `LOW`, or `NORMAL`
5. **Outputs** alerts to a local NDJSON file and/or an Elasticsearch/Kibana stack

---

## Quick Start

**Prerequisites:** Python 3.9+, pip

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the inference API (port 5000 by default)
python model_api.py

# 3. In a second terminal, run the IoT device simulator
python device_simulator.py

# 4. (Optional) In Kibana, create a data view matching: iot-alerts*
```

To run the full pipeline in one shot (API + capture + simulator):

```bash
python run_all.py
```

---

## Running from a PCAP File

```bash
python predict_from_pcap.py --pcap <file.pcap> --model api --out detections/out.ndjson
```

---

## Retraining the Model

Place a Zeek-format `conn.log.labeled` file in the project root, then:

```bash
python train_from_dataset.py
```

This overwrites `isolation_forest.joblib` with the newly trained model.

---

## API Reference

The Flask API runs on `http://localhost:5000` by default.

### `POST /predict`

Accepts a JSON object with the 6 flow features and returns an anomaly verdict.

**Request body:**

```json
{
  "duration": 0.5,
  "orig_bytes": 120,
  "resp_bytes": 900,
  "pkts": 20,
  "proto_TCP": 1,
  "proto_UDP": 0
}
```

**Response:**

```json
{
  "anomaly": true,
  "features": { ... },
  "ts": "2025-09-03T12:00:00+00:00"
}
```

`anomaly: true` means the model scored this flow as an outlier (Isolation Forest prediction = -1).

---

## Feature Schema

| Feature      | Type  | Description                        |
|--------------|-------|------------------------------------|
| `duration`   | float | Connection duration in seconds     |
| `orig_bytes` | int   | Bytes sent by the originator       |
| `resp_bytes` | int   | Bytes sent by the responder        |
| `pkts`       | int   | Total packet count                 |
| `proto_TCP`  | int   | 1 if TCP, else 0                   |
| `proto_UDP`  | int   | 1 if UDP, else 0                   |

---

## Model Performance

Evaluated on a held-out split of the IoT-23 dataset (75/25 train/test, stratified):

| Metric    | Score  |
|-----------|--------|
| Accuracy  | 96.67% |
| Precision | 85.71% |
| Recall    | 85.71% |
| F1-Score  | 85.71% |

Test set: 60 samples (52 benign, 8 malicious). Confusion matrix: 52 TN, 1 FP, 1 FN, 6 TP.

---

## Configuration

Environment variables (can be set in a `.env` file):

| Variable     | Default                  | Description                        |
|--------------|--------------------------|------------------------------------|
| `API_PORT`   | `5000`                   | Port the Flask API listens on      |
| `ES_URL`     | `http://localhost:9200`  | Elasticsearch base URL             |
| `ES_INDEX`   | `iot-alerts`             | Elasticsearch index name           |
| `MODEL_PATH` | `isolation_forest.joblib`| Path to the serialised model file  |

For advanced pipeline configuration (capture interface, severity thresholds, sinks), edit `config/config.yaml`.

---

## Project Structure

```
IoT-Anomaly-Pipeline/
├── config/
│   ├── config.yaml             # Pipeline configuration
│   └── feature_schema.json     # Feature names and types
├── pipelines/
│   ├── feature_extractor.py    # Converts raw flows to feature vectors
│   ├── infer.py                # ModelClient abstraction (local or API)
│   └── severity.py             # Maps anomaly scores to severity levels
├── detections/
│   └── c2_rules.py             # Periodic beacon detection rules
├── utils/
│   └── flow_aggregator.py      # Aggregates packets into bidirectional flows
├── docs/
│   ├── FILE_OVERVIEW.md
│   └── KIBANA_SETUP.md
├── tests/
│   └── sample_payload.json     # Example API request body
├── model_api.py                # Flask REST API (/predict)
├── device_simulator.py         # Simulates normal and anomalous IoT traffic
├── predict_from_pcap.py        # Batch inference from .pcap files
├── train_from_dataset.py       # Model training from conn.log.labeled
├── run_all.py                  # Orchestrates full pipeline demo
├── isolation_forest.joblib     # Pre-trained model (IoT-23, 2025-09-03)
├── conn.log.labeled            # Training data (Zeek format, IoT-23)
└── requirements.txt
```

---

## Dependencies

```
flask
joblib
numpy
pandas
requests
scikit-learn
python-dotenv
```

Install with `pip install -r requirements.txt`.

---

## Dataset

Training data is sourced from the [IoT-23 dataset](https://www.stratosphereips.org/datasets-iot23) — a collection of labeled network captures from real IoT devices, including malware scenarios with C&C traffic.

The included `conn.log.labeled` file is a Zeek-format connection log with `benign` and `malicious` labels.
