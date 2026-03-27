import time

class Flow:
    def __init__(self, key):
        self.key = key  # (src, dst, dport, proto)
        self.first_ts = None
        self.last_ts = None
        self.pkt_ts = []
        self.pkt_sizes = []
        self.byte_count = 0
        self.pkt_count = 0

    def add(self, ts, size):
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        self.pkt_ts.append(ts)
        self.pkt_sizes.append(size)
        self.pkt_count += 1
        self.byte_count += size

    def duration_ms(self):
        if self.first_ts and self.last_ts:
            return (self.last_ts - self.first_ts) * 1000.0
        return 0.0

    def idle_for(self, now):
        return (now - self.last_ts) if self.last_ts else 0

    def summary(self):
        (src, dst, dport, proto) = self.key
        return {
            "src_ip": src, "dst_ip": dst, "dst_port": dport,
            "proto": proto, "pkts": self.pkt_count, "orig_bytes": self.byte_count
        }

class FlowAggregator:
    def __init__(self, timeout_sec=60):
        self.timeout = timeout_sec
        self.flows = {}

    def _key(self, pkt):
        try:
            ip = pkt.ip
            src = ip.src
            dst = ip.dst
            proto = "tcp" if hasattr(pkt, "tcp") else ("udp" if hasattr(pkt, "udp") else "other")
            dport = int(pkt.tcp.dstport) if proto == "tcp" else int(pkt.udp.dstport) if proto == "udp" else 0
            size = int(pkt.length)
            ts = float(pkt.sniff_timestamp)
        except Exception:
            return None
        return (src, dst, dport, proto), ts, size

    def add_packet(self, pkt):
        out = self._key(pkt)
        if not out: return
        key, ts, size = out
        f = self.flows.get(key)
        if not f:
            f = Flow(key); self.flows[key] = f
        f.add(ts, size)

    def flush_ready(self):
        now = time.time()
        ready = [f for f in self.flows.values() if f.idle_for(now) >= self.timeout]
        for f in ready:
            del self.flows[f.key]
        return ready
