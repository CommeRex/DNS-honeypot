"""
Shared utilities for the DNS amplification honeypot analysis scripts.
Every per-sub-question script imports from this module so the data loading,
own-traffic filtering, rate-limit reconstruction, IP enrichment and figure
styling are defined in exactly one place.
"""

import json
import os
import ipaddress
import socket
import time
from collections import defaultdict

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUTPUT_DIR = "analysis_output"
CYMRU_CACHE = "geo_cache.json"

# Networks whose traffic is not external attack traffic and is filtered out
# before analysis. The generic non-routable ranges below are safe to publish.

OWN_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("10.0.0.0/8"),      # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),   # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918 private
]

_LOCAL_NETS_FILE = os.environ.get("HONEYPOT_OWN_NETWORKS", "own_networks.local")
if os.path.exists(_LOCAL_NETS_FILE):
    with open(_LOCAL_NETS_FILE) as _f:
        for _line in _f:
            _line = _line.split("#")[0].strip()
            if not _line:
                continue
            try:
                OWN_NETWORKS.append(ipaddress.ip_network(_line))
            except ValueError:
                pass

# Styling for publication figures.
plt.rcParams.update({
    "font.size": 11,
    "font.family": "sans-serif",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "figure.dpi": 100,
})
BLUE = "#0C447C"
LIGHT = "#85B7EB"
RED = "#A32D2D"

GAP = pd.Timedelta(hours=1)


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


# Loading and filtering

def is_own_ip(ip_str):
    """Return True if ip_str belongs to one of the OWN_NETWORKS."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in OWN_NETWORKS)


def load(path):
    """Load the JSONL log into separate lists by event type, filtering own IPs."""
    requests, rate_limited, attacks = [], [], []
    own_filtered = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = e.get("event_type", "request")
            src = e.get("source_ip", "")
            if et in ("request", "rate_limited") and is_own_ip(src):
                own_filtered += 1
                continue
            if et == "request":
                requests.append(e)
            elif et == "rate_limited":
                rate_limited.append(e)
            elif et in ("attack_start", "attack_end"):
                if not is_own_ip(src):
                    attacks.append(e)
    print(f"Loaded {len(requests)} external requests "
          f"({own_filtered} own-traffic packets filtered out)")
    print(f"        {len(rate_limited)} rate-limit events, "
          f"{len(attacks)} external attack events\n")
    return requests, rate_limited, attacks


# Attack sessions and rate-limit reconstruction

def build_attack_sessions(attacks):
    """Group attack_end events into per-IP sessions: ip -> [(count,start,end)]."""
    sessions = defaultdict(list)
    for a in attacks:
        if a.get("event_type") != "attack_end":
            continue
        ip = a.get("source_ip", "")
        count = a.get("attack_count", 0) or 0
        try:
            start = pd.Timestamp(a.get("attack_start"))
            end = pd.Timestamp(a.get("attack_end"))
        except Exception:
            start = end = pd.NaT
        sessions[ip].append((count, start, end))
    return dict(sessions)


def _ts(r):
    return pd.Timestamp(r["timestamp"])


def expand_for_rate_limited(requests, sessions):
    """
    Materialise packets the rate limiter dropped so every downstream statistic
    reflects true volume. For each attack session, the logged packets of the
    matching burst are replicated (cyclically, preserving the query-type/size
    mix) until the session contains attack_count packets. Duplicates are flagged
    synthetic=True. See the methodology note in the paper for the rationale.
    """
    for r in requests:
        r["synthetic"] = False

    by_ip = defaultdict(list)
    for r in requests:
        by_ip[r["source_ip"]].append(r)
    for ip in by_ip:
        by_ip[ip].sort(key=_ts)

    extra = []
    for ip, ip_sessions in sessions.items():
        pkts = by_ip.get(ip, [])
        runs = []
        for r in pkts:
            if runs and (_ts(r) - _ts(runs[-1][-1])) <= GAP:
                runs[-1].append(r)
            else:
                runs.append([r])
        used = set()
        for (count, s_start, s_end) in ip_sessions:
            if pd.isna(s_start):
                continue
            match = None
            for i, run in enumerate(runs):
                if i in used:
                    continue
                r_start, r_end = _ts(run[0]), _ts(run[-1])
                if r_start <= s_end and s_start <= (r_end + GAP):
                    match = run
                    used.add(i)
                    break
            if match is None:
                continue
            k = len(match)
            if k >= count:
                continue
            for j in range(count - k):
                dup = dict(match[j % k])
                dup["synthetic"] = True
                extra.append(dup)

    n_synth = len(extra)
    print(f"Materialised {n_synth} rate-limited packets "
          f"({len(requests)} logged -> {len(requests) + n_synth} total)\n")
    return requests + extra


def to_dataframe(requests):
    """Build a pandas DataFrame with derived columns."""
    df = pd.DataFrame(requests)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", utc=True)
    df["baf"] = df["response_size"] / df["request_size"].replace(0, pd.NA)
    df["date"] = df["timestamp"].dt.date
    df["hour"] = df["timestamp"].dt.hour

    def net24(ip):
        try:
            return str(ipaddress.ip_network(ip + "/24", strict=False).network_address)
        except ValueError:
            return "unknown"
    df["net24"] = df["source_ip"].apply(net24)
    if "synthetic" not in df.columns:
        df["synthetic"] = False
    return df


def session_true_start(df, ip, s_start, s_end):
    """First LOGGED packet of the run a session belongs to (true onset)."""
    logged = df[(df["source_ip"] == ip) & (~df["synthetic"])].sort_values("timestamp")
    times = list(logged["timestamp"])
    if not times:
        return s_start
    runs = []
    for t in times:
        if runs and (t - runs[-1][-1]) <= GAP:
            runs[-1].append(t)
        else:
            runs.append([t])
    for run in runs:
        if run[0] <= s_end and s_start <= (run[-1] + GAP):
            return run[0]
    return s_start


# IP enrichment via Team Cymru bulk WHOIS

def parse_cymru(text):
    """Parse a Team Cymru verbose bulk WHOIS response into ip -> fields."""
    result = {}
    for line in text.splitlines():
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip, prefix, cc, registry, allocated, as_name = parts[:7]
        if asn.upper() == "AS" or not ip:
            continue
        result[ip] = {
            "asn": asn,
            "country": cc if cc else "??",
            "as_name": as_name if as_name else "unknown",
        }
    return result


def cymru_bulk_lookup(ips, timeout=40):
    """Query Team Cymru for a list of IPs. Raises on connection failure."""
    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    sock = socket.create_connection(("whois.cymru.com", 43), timeout=timeout)
    try:
        sock.sendall(query.encode())
        chunks = []
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()
    return parse_cymru(b"".join(chunks).decode(errors="replace"))


def enrich_ips(ips):
    """Return ip -> {asn,country,as_name}, using a persistent local cache."""
    cache = {}
    if os.path.exists(CYMRU_CACHE):
        try:
            with open(CYMRU_CACHE) as f:
                cache = json.load(f)
        except Exception:
            cache = {}

    missing = [ip for ip in ips if ip not in cache]
    if missing:
        print(f"  enriching {len(missing)} new IPs via Team Cymru "
              f"({len(cache)} cached)...")
        BATCH = 500
        ok = True
        for i in range(0, len(missing), BATCH):
            batch = missing[i:i + BATCH]
            try:
                cache.update(cymru_bulk_lookup(batch))
                time.sleep(1)
            except Exception as e:
                print(f"  [!] Team Cymru lookup failed ({e}); "
                      f"continuing without enrichment.")
                ok = False
                break
        if ok:
            try:
                with open(CYMRU_CACHE, "w") as f:
                    json.dump(cache, f)
            except Exception:
                pass

    return {ip: cache.get(ip, {"asn": "??", "country": "??", "as_name": "unknown"})
            for ip in ips}


def add_geo(df):
    """Add country, asn and as_name columns to the dataframe."""
    ips = sorted(df["source_ip"].unique())
    info = enrich_ips(ips)
    df["country"] = df["source_ip"].map(lambda ip: info[ip]["country"])
    df["asn"] = df["source_ip"].map(lambda ip: info[ip]["asn"])
    df["as_name"] = df["source_ip"].map(lambda ip: info[ip]["as_name"])
    return df


# One-call pipeline

def prepare(path, enrich=False):
    """
    Run the full shared pipeline and return (df, sessions, rate_limited, attacks).

    df contains all external packets including the materialised rate-limited
    ones (flagged via the 'synthetic' column). Set enrich=True to add country /
    AS columns (requires internet for the first run; results are cached).
    """
    requests, rate_limited, attacks = load(path)
    sessions = build_attack_sessions(attacks)
    requests = expand_for_rate_limited(requests, sessions)
    df = to_dataframe(requests)
    if enrich:
        print("Enriching source IPs (country + AS):")
        df = add_geo(df)
        print()
    return df, sessions, rate_limited, attacks
