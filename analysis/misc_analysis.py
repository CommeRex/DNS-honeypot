"""
General overview and sanity checks for the honeypot log, independent of any one
sub-question. Produces a dataset summary table and an amplification-factor
distribution figure that give context for the rest of the analysis.

Outputs (in ./analysis_output/):
    table_summary.csv          - overall dataset statistics
    fig_baf_distribution.png   - amplification factor distribution

Usage:
    py misc_analysis.py honeypot.jsonl
"""

import sys
import os
import pandas as pd
import honeypot_common as hc


def table_summary(df, rate_limited, attacks):
    logged = int((~df["synthetic"]).sum())
    rows = {
        "Total packets (incl. rate-limited)": len(df),
        "Logged packets": logged,
        "Reconstructed rate-limited packets": len(df) - logged,
        "Unique source IPs": df["source_ip"].nunique(),
        "Unique source /24 networks": df["net24"].nunique(),
        "Unique queried domains": df["queried_domain"].nunique(),
        "Observation start (UTC)": str(df["timestamp"].min()),
        "Observation end (UTC)": str(df["timestamp"].max()),
        "Mean BAF (volume-weighted)": round(df["baf"].mean(), 2),
        "Median BAF": round(df["baf"].median(), 2),
        "Max BAF": round(df["baf"].max(), 2),
        "Packets with BAF > 2": int((df["baf"] > 2).sum()),
        "Packets with BAF > 10": int((df["baf"] > 10).sum()),
        "Rate-limit events": len(rate_limited),
        "Attack-start events (external)": sum(
            1 for a in attacks if a["event_type"] == "attack_start"),
    }
    out = pd.DataFrame(list(rows.items()), columns=["Metric", "Value"])
    path = os.path.join(hc.OUTPUT_DIR, "table_summary.csv")
    out.to_csv(path, index=False)
    print(f"  wrote {path}")
    return out


def fig_baf_distribution(df):
    import matplotlib.pyplot as plt
    baf = df["baf"].dropna()
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(baf, bins=40, color=hc.BLUE, edgecolor="white")
    ax.axvline(1.0, color="red", linestyle="--", linewidth=1,
               label="BAF = 1 (no amplification)")
    ax.set_xlabel("Bandwidth Amplification Factor (response / request)")
    ax.set_ylabel("Number of packets")
    ax.set_title("Distribution of amplification factors")
    ax.legend()
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig_baf_distribution.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "honeypot.jsonl"
    hc.ensure_output_dir()
    df, sessions, rate_limited, attacks = hc.prepare(path, enrich=False)

    print("Outputs:")
    summary = table_summary(df, rate_limited, attacks)
    fig_baf_distribution(df)

    print("\n" + "=" * 60)
    print("DATASET SUMMARY")
    print("=" * 60)
    print(summary.to_string(index=False))
    print(f"\nWritten to ./{hc.OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
