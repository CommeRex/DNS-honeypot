"""
Maps every source IP to a country and AS via Team Cymru bulk WHOIS (no signup,
cached locally). NOTE: most traffic is from scanners using their real IPs, so
this describes the geography of hosts CONTACTING the honeypot, not spoofed
victims. Only genuine attack traffic represents a true victim (see SQ4).

Outputs (in ./analysis_output/):
    fig10_source_countries.png   - top source countries by unique IPs
    fig11_source_as.png          - top source ASes by unique IPs
    table_source_countries.csv
    table_source_as.csv

Run WITH internet access (first run queries Team Cymru, then caches).

Usage:
    py sq2_geography.py honeypot.jsonl
"""

import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
import honeypot_common as hc


def fig_source_countries(df, top_n=12):
    if "country" not in df.columns or (df["country"] == "??").all():
        print("  (skipping countries figure: no geo data - run with internet)")
        return
    by_country = (df[df["country"] != "??"]
                  .groupby("country")["source_ip"].nunique()
                  .sort_values(ascending=False).head(top_n).sort_values())
    if by_country.empty:
        return
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(by_country.index, by_country.values, color=hc.BLUE)
    ax.set_xlabel("Unique source IPs")
    ax.set_title(f"Top {top_n} source countries")
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig10_source_countries.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def fig_source_as(df, top_n=12):
    if "asn" not in df.columns or (df["asn"] == "??").all():
        print("  (skipping AS figure: no geo data - run with internet)")
        return
    sub = df[df["asn"] != "??"].copy()
    if sub.empty:
        return
    sub["as_label"] = "AS" + sub["asn"].astype(str) + " " + sub["as_name"].str.slice(0, 22)
    by_as = (sub.groupby("as_label")["source_ip"].nunique()
             .sort_values(ascending=False).head(top_n).sort_values())
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(by_as.index, by_as.values, color=hc.BLUE)
    ax.set_xlabel("Unique source IPs")
    ax.set_title(f"Top {top_n} source autonomous systems")
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig11_source_as.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def table_source_countries(df, top_n=20):
    if "country" not in df.columns:
        return None
    g = df.groupby("country")
    out = pd.DataFrame({
        "unique_ips": g["source_ip"].nunique(),
        "packets": g.size(),
    }).sort_values("unique_ips", ascending=False).head(top_n)
    path = os.path.join(hc.OUTPUT_DIR, "table_source_countries.csv")
    out.to_csv(path)
    print(f"  wrote {path}")
    return out


def table_source_as(df, top_n=20):
    if "asn" not in df.columns:
        return None
    g = df.groupby(["asn", "as_name"])
    out = pd.DataFrame({
        "unique_ips": g["source_ip"].nunique(),
        "packets": g.size(),
        "country": g["country"].agg(lambda s: s.mode().iat[0] if not s.mode().empty else "??"),
    }).sort_values("unique_ips", ascending=False).head(top_n)
    path = os.path.join(hc.OUTPUT_DIR, "table_source_as.csv")
    out.to_csv(path)
    print(f"  wrote {path}")
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "honeypot.jsonl"
    hc.ensure_output_dir()
    df, sessions, rate_limited, attacks = hc.prepare(path, enrich=True)

    print("SQ2 outputs:")
    fig_source_countries(df)
    fig_source_as(df)
    table_source_countries(df)
    table_source_as(df)
    print(f"\nWritten to ./{hc.OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
