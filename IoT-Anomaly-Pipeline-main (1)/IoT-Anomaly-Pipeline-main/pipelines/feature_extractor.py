from detections.c2_rules import periodicity_stats

def extract_features(flow):
    # Map to your schema’s names
    duration = flow.duration_ms() / 1000.0
    pkts = flow.pkt_count
    # We only see total bytes; split roughly for demo (or enhance later with dir)
    orig_bytes = flow.byte_count // 2
    resp_bytes = flow.byte_count - orig_bytes

    dst_port = flow.key[2]
    proto_TCP = 1 if flow.key[3] == "tcp" else 0
    proto_UDP = 1 if flow.key[3] == "udp" else 0

    # Timing features
    ts = sorted(flow.pkt_ts)
    iats = [(ts[i]-ts[i-1])*1000.0 for i in range(1, len(ts))]
    avg_iat_ms = sum(iats)/len(iats) if iats else 0.0
    iat_jitter_ms = (sum(abs(iats[i]-iats[i-1]) for i in range(1,len(iats)))/len(iats)) if len(iats)>1 else 0.0

    b_int_ms, b_jit_ms, is_periodic = periodicity_stats(ts)

    features = {
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "pkts": pkts,
        "proto_TCP": proto_TCP,
        "proto_UDP": proto_UDP,
        "dst_port": dst_port,
        "avg_iat_ms": avg_iat_ms,
        "iat_jitter_ms": iat_jitter_ms,
        "beacon_interval_ms": b_int_ms,
        "beacon_jitter_ms": b_jit_ms,
        "domain_entropy": 0.0
    }
    c2 = {"periodic": is_periodic, "low_jitter": (b_jit_ms < 500 and is_periodic)}
    return features, c2
