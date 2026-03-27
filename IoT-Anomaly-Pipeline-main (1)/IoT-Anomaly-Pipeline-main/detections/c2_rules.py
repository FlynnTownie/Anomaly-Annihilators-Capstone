def periodicity_stats(timestamps):
    """
    Minimal periodicity heuristic:
    - Compute inter-arrival intervals.
    - Score ~ 1.0 when intervals are very consistent (beacon-like),
      lower when irregular.
    Returns a dict with fields other code might expect.
    """
    if not timestamps or len(timestamps) < 3:
        return {"periodicity": 0.0, "avg_interval": None, "std_interval": None}

    intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
    avg = sum(intervals) / len(intervals)
    var = sum((i - avg) ** 2 for i in intervals) / len(intervals)
    std = var ** 0.5
    # normalize: lower std/avg -> higher periodicity (cap to [0,1])
    score = 1.0 - (std / (avg + 1e-9))
    score = max(0.0, min(1.0, float(score)))

    return {"periodicity": score, "avg_interval": float(avg), "std_interval": float(std)}
