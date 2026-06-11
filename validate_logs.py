"""
validate_logs.py
----------------
Sanity check and summary for honeypot.jsonl.
Handles three event types:
  request      – normal DNS request that received a response
  rate_limited – first packet from an IP that was rate-limited
  attack_start – IP crossed the 100-request attack threshold
  attack_end   – attack session closed (gap > 1 hour)

Usage:
    python3 validate_logs.py honeypot.jsonl
"""

import json
import sys
from collections import Counter
from datetime import datetime, timezone

REQUEST_FIELDS = {
    "event_type", "timestamp", "source_ip", "source_port",
    "queried_domain", "query_type", "edns_payload",
    "request_size", "response_size",
}


def load_logs(path: str):
    requests, rate_limited, attacks = [], [], []
    errors = 0
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                et = entry.get("event_type", "request")
                if et == "request":
                    requests.append(entry)
                elif et == "rate_limited":
                    rate_limited.append(entry)
                elif et in ("attack_start", "attack_end"):
                    attacks.append(entry)
            except json.JSONDecodeError as e:
                print(f"  [!] Line {i}: JSON parse error: {e}")
                errors += 1

    print(f"Loaded {len(requests)} requests, {len(rate_limited)} rate-limit events, "
          f"{len(attacks)} attack events  ({errors} parse errors)\n")
    return requests, rate_limited, attacks


def validate(requests):
    missing = Counter()
    for e in requests:
        for f in REQUEST_FIELDS:
            if f not in e:
                missing[f] += 1
    if missing:
        print("Missing fields in request entries:")
        for f, c in missing.most_common():
            print(f"  {f}: missing in {c} entries")
    else:
        print("All expected fields present in every request entry.")


def summarise_requests(requests):
    if not requests:
        print("No request entries.")
        return

    ips        = Counter(e["source_ip"] for e in requests)
    domains    = Counter(e["queried_domain"] for e in requests)
    qtypes     = Counter(e["query_type"] for e in requests)
    req_sizes  = [e["request_size"] for e in requests]
    resp_sizes = [e["response_size"] for e in requests]

    timestamps = []
    for e in requests:
        try:
            timestamps.append(datetime.fromisoformat(
                e["timestamp"].replace("Z", "+00:00")))
        except Exception:
            pass

    print("── Request summary ────────────────────────────────")
    print(f"Total requests    : {len(requests)}")
    if timestamps:
        print(f"Time range        : {min(timestamps)} → {max(timestamps)}")
    print(f"Unique source IPs : {len(ips)}")
    print(f"Unique domains    : {len(domains)}")
    print()

    print("Top 10 source IPs (victim IPs during attacks):")
    for ip, c in ips.most_common(10):
        print(f"  {ip:<20} {c:>6} requests")
    print()

    print("Top 10 queried domains:")
    for d, c in domains.most_common(10):
        print(f"  {d:<40} {c:>6} requests")
    print()

    print("Query type breakdown:")
    for qt, c in qtypes.most_common():
        print(f"  {qt:<10} {c}")
    print()

    if req_sizes:
        avg_req  = sum(req_sizes)  / len(req_sizes)
        avg_resp = sum(resp_sizes) / len(resp_sizes)
        amp = avg_resp / avg_req if avg_req > 0 else 0
        print(f"Avg request size  : {avg_req:.1f} B")
        print(f"Avg response size : {avg_resp:.1f} B")
        print(f"Avg amplification : {amp:.1f}×")


def summarise_attacks(attacks):
    if not attacks:
        print("\nNo attack events recorded yet.")
        return

    starts = [a for a in attacks if a["event_type"] == "attack_start"]
    ends   = [a for a in attacks if a["event_type"] == "attack_end"]

    print("\n── Attack event summary ───────────────────────────")
    print(f"Attack starts : {len(starts)}")
    print(f"Attack ends   : {len(ends)}")

    if starts:
        attacker_ips = Counter(a["source_ip"] for a in starts)
        print("\nTop attacking IPs (by number of attack_start events):")
        for ip, c in attacker_ips.most_common(10):
            print(f"  {ip:<20} {c} session(s)")

    if ends:
        counts = [a.get("attack_count", 0) for a in ends]
        print(f"\nAvg requests per completed attack session : {sum(counts)/len(counts):.0f}")


def summarise_rate_limits(rate_limited):
    if not rate_limited:
        print("\nNo rate-limit events recorded.")
        return
    ips = Counter(e["source_ip"] for e in rate_limited)
    print(f"\n── Rate-limit summary ─────────────────────────────")
    print(f"Distinct IPs rate-limited : {len(ips)}")
    print("Top 10 rate-limited IPs:")
    for ip, c in ips.most_common(10):
        print(f"  {ip:<20} {c} block event(s)")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "honeypot.jsonl"
    print(f"Reading: {path}\n")
    requests, rate_limited, attacks = load_logs(path)
    validate(requests)
    print()
    summarise_requests(requests)
    summarise_rate_limits(rate_limited)
    summarise_attacks(attacks)
