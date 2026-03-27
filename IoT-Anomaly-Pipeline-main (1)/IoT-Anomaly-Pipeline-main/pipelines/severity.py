def grade_event(ts, device_id, flow, features, model, c2, cfg):
    score = model["score"]
    sev_cfg = cfg["severity"]
    if score >= sev_cfg["high_threshold"] and (not sev_cfg["require_periodic_for_high"] or c2["periodic"]):
        level = "HIGH"; reason = "High anomaly score" + (" + periodic beacon" if c2["periodic"] else "")
    elif score >= sev_cfg["medium_threshold"]:
        level = "MEDIUM"; reason = "Medium anomaly score"
    elif score >= sev_cfg["low_threshold"]:
        level = "LOW"; reason = "Low anomaly score"
    else:
        level = "IGNORE"; reason = "Below threshold"
    return {"ts": ts, "device_id": device_id, "flow": flow, "features": features,
            "model": model, "c2_signals": c2, "severity": {"level": level, "reason": reason}}
