"""
Temporal characteristics of attack traffic.

Outputs (in ./analysis_output/):
    fig1_requests_per_day.png    - packets per day
    fig2_requests_by_hour.png    - packets per hour of day (UTC)
    fig9_attack_timeline.png     - timeline of classified attack events
    table_attack_timing.csv      - per-event start, duration, rate, verdict

Usage:
    py sq1_temporal.py honeypot.jsonl
"""

import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates
import honeypot_common as hc


def fig_requests_per_day(df):
    per_day = df.groupby("date").size()
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar([str(d) for d in per_day.index], per_day.values, color=hc.BLUE)
    ax.set_xlabel("Date (UTC)")
    ax.set_ylabel("Number of packets (incl. rate-limited)")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig1_requests_per_day.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def fig_requests_by_hour(df):
    per_hour = df.groupby("hour").size().reindex(range(24), fill_value=0)
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(per_hour.index, per_hour.values, color=hc.BLUE)
    ax.set_xlabel("Hour of day (UTC)")
    ax.set_ylabel("Number of packets (incl. rate-limited)")
    ax.set_title("DNS requests by hour of day")
    ax.set_xticks(range(0, 24, 2))
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig2_requests_by_hour.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def table_attack_timing(df, attacks, sessions):
    starts = {a["source_ip"]: a for a in attacks if a["event_type"] == "attack_start"}
    rows = []
    for ip, ip_sessions in sessions.items():
        for (count, s_start, s_end) in ip_sessions:
            if pd.isna(s_start):
                continue
            true_start = hc.session_true_start(df, ip, s_start, s_end)
            duration = (s_end - true_start).total_seconds()
            rate = count / duration if duration > 0 else float("nan")
            mean_baf = df.loc[df["source_ip"] == ip, "baf"].mean()
            verdict = "likely attack" if (pd.notna(mean_baf) and mean_baf > 2) else "scanner / recon"
            st = starts.get(ip, {})
            rows.append({
                "start_utc": str(true_start)[:19],
                "source_ip": ip,
                "trigger_domain": st.get("domain", ""),
                "trigger_qtype": st.get("query_type", ""),
                "packets": count,
                "duration_s": round(duration),
                "duration_min": round(duration / 60, 1),
                "rate_pps": round(rate, 2),
                "mean_baf": round(mean_baf, 2) if pd.notna(mean_baf) else "n/a",
                "verdict": verdict,
            })
    out = pd.DataFrame(rows).sort_values("start_utc")
    path = os.path.join(hc.OUTPUT_DIR, "table_attack_timing.csv")
    out.to_csv(path, index=False)
    print(f"  wrote {path}")
    return out


def fig_attack_timeline(timing):
    if timing.empty:
        return
    t = timing.copy()
    t["start"] = pd.to_datetime(t["start_utc"], utc=True)
    t["end"] = t["start"] + pd.to_timedelta(t["duration_s"], unit="s")
    t = t.sort_values("start").reset_index(drop=True)

    fig, ax = plt.subplots(figsize=(9, 4))
    for i, row in t.iterrows():
        color = hc.RED if row["verdict"] == "likely attack" else hc.BLUE
        start_num = matplotlib.dates.date2num(row["start"])
        width = max((row["end"] - row["start"]).total_seconds() / 86400, 0.05)
        ax.barh(i, width, left=start_num, color=color, height=0.6)
        ax.text(start_num, i, f" {row['source_ip']} ({row['trigger_qtype']})",
                va="center", ha="left", fontsize=8)
    ax.set_yticks([])
    ax.xaxis_date()
    fig.autofmt_xdate()
    ax.set_xlabel("Date (UTC)")
    ax.set_title("Timeline of classified attack events")
    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(facecolor=hc.RED, label="likely attack"),
        Patch(facecolor=hc.BLUE, label="scanner / recon"),
    ], loc="lower right")
    plt.tight_layout()
    path = os.path.join(hc.OUTPUT_DIR, "fig9_attack_timeline.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"  wrote {path}")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "honeypot.jsonl"
    hc.ensure_output_dir()
    df, sessions, rate_limited, attacks = hc.prepare(path, enrich=False)

    print("SQ1 outputs:")
    fig_requests_per_day(df)
    fig_requests_by_hour(df)
    timing = table_attack_timing(df, attacks, sessions)
    fig_attack_timeline(timing)

    print("\nAttack timing:")
    print(timing.to_string(index=False))
    print(f"\nWritten to ./{hc.OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
