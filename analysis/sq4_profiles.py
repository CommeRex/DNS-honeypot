"""
With only a few of classified attack events, statistical clustering is not meaningful. 
This script instead characterises sources
descriptively: it ranks them by true volume, plots volume against amplification,
and classifies each attack-start event as a likely attack or a scanner based on
the amplification factor of its traffic.

Outputs (in ./analysis_output/):
    fig6_attacker_scatter.png    - per-source volume vs mean BAF
    fig8_top_sources_volume.png  - top sources by volume (incl. rate-limited)
    table_top_sources.csv        - per-source behaviour summary
    table_attack_events.csv      - classified attack-start events with verdict

Usage:
    py sq4_profiles.py honeypot.jsonl
"""

import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import honeypot_common as hc

ATTACK_BAF = 2.0
HIGH_BAF = 10.0
RECON_DOMAINS = {"version.bind.", "hostname.bind.", "id.server.", "."}


def assign_profiles(df, sessions):
    """
    Assign each source IP to a behavioural profile.

    The profiles are derived from the data rather than from a clustering
    algorithm: with so few high-volume sources, a descriptive taxonomy is more
    honest and more interpretable than DBSCAN on a handful of points. Each
    source is placed in the first matching category, in priority order:

      high-BAF reflector prober : mean BAF >= 10 (testing a high-yield amplifier)
      amplification attack      : triggered the classifier AND mean BAF > 2
      fingerprint scanner       : mainly queries version.bind / id.server / root
      low-volume background     : <= 3 packets total
      other scanner / recon     : everything else
    """
    g = df.groupby("source_ip")
    vol = g.size()
    mean_baf = g["baf"].mean()
    dom_domain = g["queried_domain"].agg(
        lambda s: s.mode().iat[0] if not s.mode().empty else "")
    triggered = {ip for ip in sessions}

    def profile(ip):
        v = vol[ip]
        b = mean_baf[ip]
        d = dom_domain[ip]
        if pd.notna(b) and b >= HIGH_BAF:
            return "high-BAF reflector prober"
        if ip in triggered and pd.notna(b) and b > ATTACK_BAF:
            return "amplification attack"
        if str(d).lower() in RECON_DOMAINS:
            return "fingerprint scanner"
        if v <= 3:
            return "low-volume background"
        return "other scanner / recon"

    return pd.Series({ip: profile(ip) for ip in vol.index}, name="profile")


def table_attacker_profiles(df, sessions):
    profiles = assign_profiles(df, sessions)
    vol = df.groupby("source_ip").size()
    baf = df.groupby("source_ip")["baf"].mean()
    frame = pd.DataFrame({"profile": profiles, "volume": vol, "baf": baf})
    out = frame.groupby("profile").agg(
        unique_ips=("profile", "size"),
        total_packets=("volume", "sum"),
        mean_baf=("baf", "mean"),
        median_volume=("volume", "median"),
    ).round(2).sort_values("total_packets", ascending=False)
    path = os.path.join(hc.OUTPUT_DIR, "table_attacker_profiles.csv")
    out.to_csv(path)
    print(f"  wrote {path}")
    return out


def fig_attacker_profiles(df, sessions):
    profiles = assign_profiles(df, sessions)
    counts = profiles.value_counts().sort_values()
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh(counts.index, counts.values, color=hc.BLUE)
    ax.set_xlabel("Number of unique source IPs")
    ax.set_title("Source IPs by behavioural profile")
    for i, v in enumerate(counts.values):
        ax.text(v, i, f" {int(v)}", va="center", fontsize=9)
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig12_attacker_profiles.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def fig_attacker_scatter(df, sessions):
    vol = df.groupby("source_ip").size()
    mean_baf = df.groupby("source_ip")["baf"].mean()
    grp = pd.DataFrame({"volume": vol, "mean_baf": mean_baf}).dropna()
    triggered = pd.Series({ip: True for ip in sessions})
    grp["triggered"] = triggered.reindex(grp.index).fillna(False).astype(bool)

    fig, ax = plt.subplots(figsize=(8, 5))
    normal = grp[~grp["triggered"]]
    fired = grp[grp["triggered"]]
    ax.scatter(normal["volume"], normal["mean_baf"], s=30, alpha=0.5,
               color=hc.LIGHT, edgecolor="none", label="below attack threshold")
    ax.scatter(fired["volume"], fired["mean_baf"], s=70, alpha=0.9,
               color=hc.BLUE, edgecolor="black", linewidth=0.5,
               label="classified as attack")
    ax.axhline(1.0, color="red", linestyle="--", linewidth=1, label="BAF = 1")
    ax.set_xscale("log")
    ax.set_xlabel("Packets from source IP (log scale)")
    ax.set_ylabel("Mean amplification factor (BAF)")
    ax.legend()
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig6_attacker_scatter.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def fig_top_sources_volume(df, sessions, top_n=12):
    vol = df.groupby("source_ip").size().sort_values(ascending=False).head(top_n)
    triggered = pd.Series({ip: True for ip in sessions}).reindex(vol.index).fillna(False)
    order = vol.iloc[::-1]
    colors = [hc.RED if triggered[ip] else hc.BLUE for ip in order.index]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(order.index, order.values, color=colors)
    ax.set_xlabel("Packets sent (incl. rate-limited)")
    ax.set_title(f"Top {top_n} source IPs by volume")
    ax.legend(handles=[
        Patch(facecolor=hc.RED, label="triggered attack classifier"),
        Patch(facecolor=hc.BLUE, label="below threshold"),
    ])
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig8_top_sources_volume.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def table_top_sources(df, sessions, top_n=20):
    g = df.groupby("source_ip")
    logged = df[~df["synthetic"]].groupby("source_ip").size()
    out = pd.DataFrame({
        "total_volume": g.size(),
        "logged_requests": logged,
        "unique_domains": g["queried_domain"].nunique(),
        "mean_baf": g["baf"].mean().round(2),
        "dominant_qtype": g["query_type"].agg(lambda s: s.mode().iat[0] if not s.mode().empty else "?"),
        "first_seen": g["timestamp"].min(),
        "last_seen": g["timestamp"].max(),
    })
    out["logged_requests"] = out["logged_requests"].fillna(0).astype(int)
    out["attack_sessions"] = pd.Series({ip: len(s) for ip, s in sessions.items()}).reindex(out.index).fillna(0).astype(int)
    out = out.sort_values("total_volume", ascending=False).head(top_n)
    out = out[["total_volume", "logged_requests", "attack_sessions",
               "unique_domains", "mean_baf", "dominant_qtype",
               "first_seen", "last_seen"]]
    path = os.path.join(hc.OUTPUT_DIR, "table_top_sources.csv")
    out.to_csv(path)
    print(f"  wrote {path}")
    return out


def table_attack_events(df, attacks):
    """
    Classify each external attack-start event as a likely amplification attack
    or a scanner. The classifier fires on request count alone, so events must be
    checked for amplification potential (mean BAF) before being treated as real
    attacks.
    """
    starts = [a for a in attacks if a["event_type"] == "attack_start"]
    rows = []
    for s in starts:
        ip = s["source_ip"]
        sub = df[df["source_ip"] == ip]
        mean_baf = sub["baf"].mean() if len(sub) else float("nan")
        verdict = "likely attack" if (pd.notna(mean_baf) and mean_baf > ATTACK_BAF) else "scanner / recon"
        rows.append({
            "timestamp": s["timestamp"],
            "source_ip": ip,
            "trigger_domain": s.get("domain", ""),
            "trigger_qtype": s.get("query_type", ""),
            "attack_count": s.get("attack_count", ""),
            "mean_baf_of_source": round(mean_baf, 2) if pd.notna(mean_baf) else "n/a",
            "verdict": verdict,
        })
    out = pd.DataFrame(rows)
    path = os.path.join(hc.OUTPUT_DIR, "table_attack_events.csv")
    out.to_csv(path, index=False)
    print(f"  wrote {path}")
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "honeypot.jsonl"
    hc.ensure_output_dir()
    df, sessions, rate_limited, attacks = hc.prepare(path, enrich=False)

    print("SQ4 outputs:")
    fig_attacker_scatter(df, sessions)
    fig_top_sources_volume(df, sessions)
    fig_attacker_profiles(df, sessions)
    table_top_sources(df, sessions)
    profiles = table_attacker_profiles(df, sessions)
    events = table_attack_events(df, attacks)

    print("\nAttacker profiles:")
    print(profiles.to_string())
    print("\nClassified attack-start events:")
    print(events.to_string(index=False))
    print(f"\nWritten to ./{hc.OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
