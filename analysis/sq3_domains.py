"""
sq3_domains.py
==============
SQ3 - Abused domains and query types.

Outputs (in ./analysis_output/):
    fig3_query_types.png         - query type distribution (incl. rate-limited)
    fig5_top_domains_baf.png     - mean BAF for the most-queried domains
    table_query_types.csv        - per query type: packets and BAF
    table_top_domains.csv        - AmpPot Table 2 replica (domain, qtype, BAF, ...)
    table_query_class.csv        - ANY vs DNSKEY vs NSEC3 vs other (RFC 8482 angle)
    table_high_baf_probing.csv   - repeated high-BAF queries from multiple sources
                                   (reflector-validation / pre-attack scanning)

Usage:
    python3 sq3_domains.py honeypot.jsonl
"""

import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
import honeypot_common as hc

# Query types that still yield large responses on DNSSEC-signed zones and that an
# attacker might shift to after RFC 8482 discouraged ANY.
POST_RFC8482_TYPES = ["ANY", "DNSKEY", "NSEC3", "NSEC", "RRSIG"]
# Threshold above which a response is a meaningful amplifier worth probing for.
HIGH_BAF = 10.0


def fig_query_types(df):
    counts = df["query_type"].value_counts()
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(counts.index, counts.values, color=hc.BLUE)
    ax.set_xlabel("Query type")
    ax.set_ylabel("Number of packets (incl. rate-limited)")
    for i, v in enumerate(counts.values):
        ax.text(i, v + max(counts.values) * 0.01, str(int(v)),
                ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig3_query_types.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def fig_top_domains_baf(df, top_n=12):
    grp = df.groupby("queried_domain").agg(
        count=("baf", "size"),
        mean_baf=("baf", "mean"),
    ).sort_values("count", ascending=False).head(top_n).sort_values("mean_baf")
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = [hc.BLUE if b > 1 else "#bbbbbb" for b in grp["mean_baf"]]
    ax.barh(grp.index, grp["mean_baf"], color=colors)
    ax.axvline(1.0, color="red", linestyle="--", linewidth=1)
    ax.set_xlabel("Mean amplification factor (BAF)")
    ax.set_title(f"Mean BAF for the {top_n} most-queried domains")
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig5_top_domains_baf.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def table_query_types(df):
    g = df.groupby("query_type")
    logged = df[~df["synthetic"]].groupby("query_type").size()
    out = pd.DataFrame({
        "total_packets": g.size(),
        "logged_packets": logged,
        "share_pct": (g.size() / len(df) * 100).round(1),
        "mean_baf": g["baf"].mean().round(2),
        "max_baf": g["baf"].max().round(2),
    })
    out["logged_packets"] = out["logged_packets"].fillna(0).astype(int)
    out = out.sort_values("total_packets", ascending=False)
    path = os.path.join(hc.OUTPUT_DIR, "table_query_types.csv")
    out.to_csv(path)
    print(f"  wrote {path}")
    return out


def table_top_domains(df, top_n=20):
    """Replicates the structure of Table 2 in Kraemer et al. (AmpPot)."""
    g = df.groupby(["queried_domain", "query_type"])
    logged = df[~df["synthetic"]].groupby(["queried_domain", "query_type"]).size()
    out = pd.DataFrame({
        "total_packets": g.size(),
        "logged_packets": logged,
        "unique_src": g["source_ip"].nunique(),
        "mean_req_size": g["request_size"].mean().round(1),
        "mean_resp_size": g["response_size"].mean().round(1),
        "mean_baf": g["baf"].mean().round(1),
        "max_edns": g["edns_payload"].max(),
    })
    out["logged_packets"] = out["logged_packets"].fillna(0).astype(int)
    out = out.sort_values("total_packets", ascending=False).head(top_n)
    path = os.path.join(hc.OUTPUT_DIR, "table_top_domains.csv")
    out.to_csv(path)
    print(f"  wrote {path}")
    return out


def table_query_class(df):
    """
    RFC 8482 angle: how much traffic uses ANY versus the alternative high-yield
    query types (DNSKEY, NSEC3, ...) that attackers might shift to, versus
    ordinary types. RFC 8482 (2019) discouraged ANY; this quantifies whether ANY
    is still in use and whether the named alternatives have appeared.
    """
    total = len(df)
    def share(mask):
        n = int(mask.sum())
        return n, round(100 * n / total, 1)
    any_n, any_p = share(df["query_type"] == "ANY")
    alt_mask = df["query_type"].isin([t for t in POST_RFC8482_TYPES if t != "ANY"])
    alt_n, alt_p = share(alt_mask)
    other_n, other_p = share(~df["query_type"].isin(POST_RFC8482_TYPES))
    rows = [
        {"class": "ANY", "packets": any_n, "share_pct": any_p,
         "mean_baf": round(df.loc[df["query_type"] == "ANY", "baf"].mean(), 2) if any_n else "n/a"},
        {"class": "DNSKEY/NSEC3/NSEC/RRSIG (post-RFC8482 alternatives)",
         "packets": alt_n, "share_pct": alt_p,
         "mean_baf": round(df.loc[alt_mask, "baf"].mean(), 2) if alt_n else "n/a"},
        {"class": "other (A, TXT, AAAA, NS, ...)", "packets": other_n, "share_pct": other_p,
         "mean_baf": round(df.loc[~df["query_type"].isin(POST_RFC8482_TYPES), "baf"].mean(), 2) if other_n else "n/a"},
    ]
    out = pd.DataFrame(rows)
    path = os.path.join(hc.OUTPUT_DIR, "table_query_class.csv")
    out.to_csv(path, index=False)
    print(f"  wrote {path}")
    return out


def table_high_baf_probing(df, min_baf=HIGH_BAF):
    """
    Detect reflector-validation / pre-attack scanning: (domain, query type)
    pairs that produce a high amplification factor AND are queried by several
    distinct source IPs, especially across a shared source network. This is the
    behaviour seen for google.com TXT (BAF ~28) from multiple 185.242.3.0/24
    hosts, which the request-count classifier never flags as an attack.
    """
    hi = df[df["baf"] >= min_baf]
    if hi.empty:
        print("  (no high-BAF traffic above threshold)")
        return pd.DataFrame()
    g = hi.groupby(["queried_domain", "query_type"])
    out = pd.DataFrame({
        "packets": g.size(),
        "unique_src": g["source_ip"].nunique(),
        "unique_net24": g["net24"].nunique(),
        "mean_baf": g["baf"].mean().round(1),
        "max_edns": g["edns_payload"].max(),
    }).sort_values(["unique_src", "packets"], ascending=False)
    path = os.path.join(hc.OUTPUT_DIR, "table_high_baf_probing.csv")
    out.to_csv(path)
    print(f"  wrote {path}")
    return out


def table_edns(df):
    """
    EDNS0 buffer advertised in received queries, with amplification per size.
    The edns_payload field is taken from each incoming request (the buffer the
    requester advertised), not set by the honeypot. Amplification is only
    possible when a large buffer is advertised, so this links request structure
    to the observed BAF.
    """
    n = len(df)
    g = df.groupby("edns_payload")
    out = pd.DataFrame({
        "packets": g.size(),
        "share_pct": (g.size() / n * 100).round(1),
        "mean_baf": g["baf"].mean().round(2),
        "max_baf": g["baf"].max().round(2),
    }).sort_index()
    out.index.name = "edns_buffer_bytes"
    path = os.path.join(hc.OUTPUT_DIR, "table_edns.csv")
    out.to_csv(path)
    print(f"  wrote {path}")
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "honeypot.jsonl"
    hc.ensure_output_dir()
    df, sessions, rate_limited, attacks = hc.prepare(path, enrich=False)

    print("SQ3 outputs:")
    fig_query_types(df)
    fig_top_domains_baf(df)
    table_query_types(df)
    table_top_domains(df)
    qclass = table_query_class(df)
    edns = table_edns(df)
    probing = table_high_baf_probing(df)

    print("\nQuery class (RFC 8482 angle):")
    print(qclass.to_string(index=False))
    print("\nEDNS0 buffer vs amplification:")
    print(edns.to_string())
    if not probing.empty:
        print("\nHigh-BAF multi-source probing:")
        print(probing.to_string())
    print(f"\nWritten to ./{hc.OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
