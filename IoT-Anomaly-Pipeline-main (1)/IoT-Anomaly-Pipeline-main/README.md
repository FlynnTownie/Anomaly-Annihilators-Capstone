# IoT Anomaly Pipeline (Isolation Forest trained from IoT-23)

Trained directly on your uploaded `conn.log.labeled` on 2025-09-03.

## Quick Start
1. pip install -r requirements.txt
2. python model_api.py
3. In another terminal: python device_simulator.py
4. In Kibana, create data view `iot-alerts*`.

## Files
- isolation_forest.joblib — trained model from IoT-23
- model_api.py — Flask API exposing /predict
- device_simulator.py — simulated IoT host
- train_from_dataset.py — retrain from conn.log.labeled
- docs/FILE_OVERVIEW.md, docs/KIBANA_SETUP.md
# IoT-Anomaly-Pipeline
