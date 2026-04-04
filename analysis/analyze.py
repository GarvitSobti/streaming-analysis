#!/usr/bin/env python3
"""
analyze.py — CS204 Streaming Platform Performance Analyser
===========================================================
Reads the CSVs produced by extract_metrics.sh and computes:
  - RTT          : mean, median, 95th percentile (ms)
  - Jitter       : mean absolute deviation and std dev of inter-arrival times (ms)
  - Avg Bitrate  : mean throughput over 1-second windows (Kbps)
  - Bitrate StdDev: standard deviation of per-second throughput (Kbps)
  - Protocol     : fraction of traffic that is TCP / UDP / QUIC

Usage
-----
    # analyse a single capture (provide any of its 4 CSV files or the pcap name):
    python analyze.py --results ../results --platform youtube --stream_type dynamic

    # analyse ALL captures found in ../results and produce comparison charts:
    python analyze.py --results ../results --compare

    # analyse a specific set of CSV files manually:
    python analyze.py --rtt    ../results/youtube_dynamic_20250101_120000_rtt.csv \
                      --timing ../results/youtube_dynamic_20250101_120000_timing.csv \
                      --proto  ../results/youtube_dynamic_20250101_120000_protocols.csv \
                      --handshake ../results/youtube_dynamic_20250101_120000_handshake.csv
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")          # headless — saves PNG files instead of opening windows
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


# ── Colour palette (one per platform) ────────────────────────────────────────
PLATFORM_COLOURS = {
    "youtube":   "#FF0000",
    "twitch":    "#9146FF",
    "tiktok":    "#010101",
    "instagram": "#E1306C",
    "unknown":   "#888888",
}

STREAM_MARKERS = {"dynamic": "o", "static": "s"}


# ═════════════════════════════════════════════════════════════════════════════
# 1.  Per-capture metric calculators
# ═════════════════════════════════════════════════════════════════════════════

def compute_rtt(rtt_csv: str) -> dict:
    """
    Parse the _rtt.csv file (tcp.analysis.ack_rtt column) and return stats in ms.
    """
    try:
        df = pd.read_csv(rtt_csv)
    except Exception as e:
        return {"error": str(e)}

    col = "tcp.analysis.ack_rtt"
    if col not in df.columns:
        return {"error": f"Column '{col}' not found. Columns: {list(df.columns)}"}

    rtt_s = pd.to_numeric(df[col], errors="coerce").dropna()
    if rtt_s.empty:
        return {"error": "No valid RTT values found"}

    rtt_ms = rtt_s * 1000  # convert seconds → ms

    return {
        "count":       int(len(rtt_ms)),
        "mean_ms":     float(rtt_ms.mean()),
        "median_ms":   float(rtt_ms.median()),
        "p95_ms":      float(rtt_ms.quantile(0.95)),
        "min_ms":      float(rtt_ms.min()),
        "max_ms":      float(rtt_ms.max()),
        "std_ms":      float(rtt_ms.std()),
        "series_ms":   rtt_ms.tolist(),
    }


def compute_handshake_rtt(handshake_csv: str) -> dict:
    """
    Parse the _handshake.csv file.
    For each SYN (ack=0), find the matching SYN-ACK (syn=1, ack=1) on the same port pair.
    RTT = t(SYN-ACK) - t(SYN).
    """
    try:
        df = pd.read_csv(handshake_csv)
    except Exception as e:
        return {"error": str(e)}

    needed = {"frame.time_relative", "tcp.flags.syn", "tcp.flags.ack",
              "tcp.srcport", "tcp.dstport", "ip.src", "ip.dst"}
    if not needed.issubset(df.columns):
        return {"error": f"Missing columns. Found: {list(df.columns)}"}

    df["frame.time_relative"] = pd.to_numeric(df["frame.time_relative"], errors="coerce")
    df["tcp.flags.syn"]       = pd.to_numeric(df["tcp.flags.syn"], errors="coerce")
    df["tcp.flags.ack"]       = pd.to_numeric(df["tcp.flags.ack"], errors="coerce")

    syns     = df[(df["tcp.flags.syn"] == 1) & (df["tcp.flags.ack"] == 0)].copy()
    syn_acks = df[(df["tcp.flags.syn"] == 1) & (df["tcp.flags.ack"] == 1)].copy()

    rtts_ms = []
    for _, syn in syns.iterrows():
        # The SYN-ACK comes back with src/dst swapped
        match = syn_acks[
            (syn_acks["ip.src"]     == syn["ip.dst"]) &
            (syn_acks["ip.dst"]     == syn["ip.src"]) &
            (syn_acks["tcp.dstport"] == syn["tcp.srcport"]) &
            (syn_acks["frame.time_relative"] > syn["frame.time_relative"])
        ]
        if not match.empty:
            rtt = (match.iloc[0]["frame.time_relative"] - syn["frame.time_relative"]) * 1000
            if 0 < rtt < 2000:   # sanity-check: 0–2 s
                rtts_ms.append(rtt)

    if not rtts_ms:
        return {"error": "No SYN/SYN-ACK pairs matched"}

    return {
        "handshake_count": len(rtts_ms),
        "mean_ms":         float(np.mean(rtts_ms)),
        "min_ms":          float(np.min(rtts_ms)),
        "max_ms":          float(np.max(rtts_ms)),
        "values_ms":       rtts_ms,
    }


def compute_jitter(timing_csv: str, min_frame_bytes: int = 500) -> dict:
    """
    Parse _timing.csv and compute inter-arrival jitter for large frames.
    Jitter = std dev of frame.time_delta (in ms).
    Also compute RFC 3550 running jitter estimate for reference.
    """
    try:
        df = pd.read_csv(timing_csv)
    except Exception as e:
        return {"error": str(e)}

    needed = {"frame.time_delta", "frame.len"}
    if not needed.issubset(df.columns):
        return {"error": f"Missing columns. Found: {list(df.columns)}"}

    df["frame.len"]        = pd.to_numeric(df["frame.len"], errors="coerce")
    df["frame.time_delta"] = pd.to_numeric(df["frame.time_delta"], errors="coerce")

    # Filter to large frames (video payload) only
    large = df[df["frame.len"] >= min_frame_bytes].copy()
    if large.empty:
        return {"error": f"No frames >= {min_frame_bytes} bytes"}

    deltas_ms = (large["frame.time_delta"].dropna() * 1000)
    # Remove the very first delta (often artificially large)
    deltas_ms = deltas_ms.iloc[1:]

    if deltas_ms.empty:
        return {"error": "Insufficient data after filtering"}

    # RFC 3550 running jitter
    rfc_jitter = 0.0
    prev = deltas_ms.iloc[0]
    rfc_values = []
    for d in deltas_ms:
        diff = abs(d - prev)
        rfc_jitter += (diff - rfc_jitter) / 16.0
        rfc_values.append(rfc_jitter)
        prev = d

    return {
        "count":          int(len(deltas_ms)),
        "mean_delta_ms":  float(deltas_ms.mean()),
        "std_ms":         float(deltas_ms.std()),           # our primary jitter metric
        "mad_ms":         float((deltas_ms - deltas_ms.mean()).abs().mean()),
        "p95_delta_ms":   float(deltas_ms.quantile(0.95)),
        "rfc3550_jitter_ms": float(rfc_values[-1]) if rfc_values else 0.0,
        "series_ms":      deltas_ms.tolist(),
        "min_frame_filter": min_frame_bytes,
    }


def compute_bitrate(timing_csv: str, window_sec: float = 1.0) -> dict:
    """
    Compute per-second throughput from _timing.csv.
    Returns avg bitrate (Kbps) and std dev of bitrate (Kbps).
    """
    try:
        df = pd.read_csv(timing_csv)
    except Exception as e:
        return {"error": str(e)}

    needed = {"frame.time_epoch", "frame.len"}
    if not needed.issubset(df.columns):
        needed2 = {"frame.time_relative", "frame.len"}
        if not needed2.issubset(df.columns):
            return {"error": f"Missing columns. Found: {list(df.columns)}"}
        # Fall back to relative time if epoch not available
        df["frame.time_epoch"] = pd.to_numeric(df["frame.time_relative"], errors="coerce")
    else:
        df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")

    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")
    df = df.dropna(subset=["frame.time_epoch", "frame.len"])

    if df.empty:
        return {"error": "No valid timing data"}

    # Bin packets into 1-second windows
    t_min = df["frame.time_epoch"].min()
    df["window"] = ((df["frame.time_epoch"] - t_min) / window_sec).astype(int)

    per_window = df.groupby("window")["frame.len"].sum()   # bytes per window
    bitrate_kbps = (per_window * 8 / window_sec) / 1000   # Kbps

    if bitrate_kbps.empty:
        return {"error": "No windows found"}

    return {
        "window_sec":      window_sec,
        "window_count":    int(len(bitrate_kbps)),
        "mean_kbps":       float(bitrate_kbps.mean()),
        "std_kbps":        float(bitrate_kbps.std()),
        "median_kbps":     float(bitrate_kbps.median()),
        "p5_kbps":         float(bitrate_kbps.quantile(0.05)),
        "p95_kbps":        float(bitrate_kbps.quantile(0.95)),
        "max_kbps":        float(bitrate_kbps.max()),
        "cv":              float(bitrate_kbps.std() / bitrate_kbps.mean()) if bitrate_kbps.mean() > 0 else 0,
        "series_kbps":     bitrate_kbps.tolist(),
        "series_index":    bitrate_kbps.index.tolist(),
    }


def compute_protocol_split(protocols_csv: str) -> dict:
    """
    Count bytes and packets by transport protocol.
    ip.proto: 6=TCP, 17=UDP; QUIC runs over UDP port 443.
    """
    try:
        df = pd.read_csv(protocols_csv)
    except Exception as e:
        return {"error": str(e)}

    needed = {"ip.proto", "frame.len"}
    if not needed.issubset(df.columns):
        return {"error": f"Missing columns. Found: {list(df.columns)}"}

    df["ip.proto"] = pd.to_numeric(df["ip.proto"], errors="coerce")
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")
    df = df.dropna(subset=["ip.proto", "frame.len"])

    proto_map = {6: "TCP", 17: "UDP"}
    df["proto_name"] = df["ip.proto"].map(proto_map).fillna("Other")

    by_bytes   = df.groupby("proto_name")["frame.len"].sum()
    by_packets = df.groupby("proto_name")["frame.len"].count()
    total_bytes = by_bytes.sum()

    # Detect QUIC: if frame.protocols column available, count "quic" occurrences
    quic_pct = 0.0
    if "frame.protocols" in df.columns:
        quic_mask = df["frame.protocols"].str.contains("quic", case=False, na=False)
        quic_bytes = df.loc[quic_mask, "frame.len"].sum()
        quic_pct = (quic_bytes / total_bytes * 100) if total_bytes > 0 else 0.0

    result = {"quic_pct_bytes": round(quic_pct, 1)}
    for proto in by_bytes.index:
        pct = by_bytes[proto] / total_bytes * 100 if total_bytes > 0 else 0
        result[proto] = {
            "bytes":   int(by_bytes[proto]),
            "packets": int(by_packets[proto]),
            "pct":     round(pct, 1),
        }
    return result


# ═════════════════════════════════════════════════════════════════════════════
# 2.  Auto-discovery of CSV sets from a results directory
# ═════════════════════════════════════════════════════════════════════════════

def discover_captures(results_dir: str) -> list[dict]:
    """
    Scan results_dir for _rtt.csv files; reconstruct the full CSV set for each capture.
    Returns a list of dicts with keys: platform, stream_type, timestamp, files{rtt,timing,handshake,protocols}
    """
    captures = []
    rtt_files = glob.glob(os.path.join(results_dir, "*_rtt.csv"))

    for rtt_path in sorted(rtt_files):
        base = os.path.basename(rtt_path).replace("_rtt.csv", "")
        # Expected format: <platform>_<stream_type>_<timestamp>
        parts = base.split("_")
        platform    = parts[0] if len(parts) > 0 else "unknown"
        stream_type = parts[1] if len(parts) > 1 else "unknown"

        capture = {
            "platform":    platform,
            "stream_type": stream_type,
            "base":        base,
            "files": {
                "rtt":       rtt_path,
                "timing":    rtt_path.replace("_rtt.csv", "_timing.csv"),
                "handshake": rtt_path.replace("_rtt.csv", "_handshake.csv"),
                "protocols": rtt_path.replace("_rtt.csv", "_protocols.csv"),
            },
        }
        captures.append(capture)

    return captures


# ═════════════════════════════════════════════════════════════════════════════
# 3.  Single-capture analysis entry point
# ═════════════════════════════════════════════════════════════════════════════

def analyse_capture(files: dict, label: str = "") -> dict:
    """Run all four metric calculators on one set of CSV files."""
    results = {"label": label}

    if os.path.exists(files.get("rtt", "")):
        results["rtt"]          = compute_rtt(files["rtt"])
        results["handshake_rtt"] = compute_handshake_rtt(files.get("handshake", ""))
    else:
        results["rtt"] = {"error": "File not found"}

    if os.path.exists(files.get("timing", "")):
        results["jitter"]  = compute_jitter(files["timing"])
        results["bitrate"] = compute_bitrate(files["timing"])
    else:
        results["jitter"]  = {"error": "File not found"}
        results["bitrate"] = {"error": "File not found"}

    if os.path.exists(files.get("protocols", "")):
        results["protocols"] = compute_protocol_split(files["protocols"])
    else:
        results["protocols"] = {"error": "File not found"}

    return results


def print_summary(results: dict):
    """Pretty-print a single capture's metrics to stdout."""
    lbl = results.get("label", "Capture")
    print(f"\n{'='*55}")
    print(f"  {lbl}")
    print(f"{'='*55}")

    # RTT
    rtt = results.get("rtt", {})
    if "error" not in rtt:
        print(f"\n  RTT (TCP ACK):")
        print(f"    Mean   : {rtt['mean_ms']:.2f} ms")
        print(f"    Median : {rtt['median_ms']:.2f} ms")
        print(f"    95th % : {rtt['p95_ms']:.2f} ms")
        print(f"    Std Dev: {rtt['std_ms']:.2f} ms")
        print(f"    Samples: {rtt['count']}")
    else:
        print(f"\n  RTT: {rtt['error']}")

    hs_rtt = results.get("handshake_rtt", {})
    if "error" not in hs_rtt:
        print(f"\n  Handshake RTT:")
        print(f"    Mean   : {hs_rtt['mean_ms']:.2f} ms  (from {hs_rtt['handshake_count']} SYN/SYN-ACK pairs)")

    # Jitter
    jitter = results.get("jitter", {})
    if "error" not in jitter:
        print(f"\n  Jitter (inter-arrival, large frames only):")
        print(f"    Std Dev        : {jitter['std_ms']:.3f} ms  ← primary metric")
        print(f"    Mean Abs Dev   : {jitter['mad_ms']:.3f} ms")
        print(f"    RFC 3550 est.  : {jitter['rfc3550_jitter_ms']:.3f} ms")
        print(f"    95th % delta   : {jitter['p95_delta_ms']:.3f} ms")
        print(f"    Samples        : {jitter['count']}")
    else:
        print(f"\n  Jitter: {jitter['error']}")

    # Bitrate
    br = results.get("bitrate", {})
    if "error" not in br:
        print(f"\n  Bitrate (1-second windows):")
        print(f"    Mean    : {br['mean_kbps']:.1f} Kbps  ({br['mean_kbps']/1000:.2f} Mbps)")
        print(f"    Std Dev : {br['std_kbps']:.1f} Kbps  ← stability metric")
        print(f"    CV      : {br['cv']:.3f}  (std/mean, lower = more stable)")
        print(f"    p5–p95  : {br['p5_kbps']:.0f}–{br['p95_kbps']:.0f} Kbps")
        print(f"    Windows : {br['window_count']}")
    else:
        print(f"\n  Bitrate: {br['error']}")

    # Protocols
    proto = results.get("protocols", {})
    if "error" not in proto:
        print(f"\n  Protocol split (by bytes):")
        for key in ["TCP", "UDP", "Other"]:
            if key in proto:
                p = proto[key]
                print(f"    {key:6s}: {p['pct']:5.1f}%  ({p['packets']} pkts)")
        if proto.get("quic_pct_bytes", 0) > 0:
            print(f"    QUIC  : {proto['quic_pct_bytes']:5.1f}%  (subset of UDP)")
    else:
        print(f"\n  Protocols: {proto['error']}")

    print()


# ═════════════════════════════════════════════════════════════════════════════
# 4.  Comparison chart generation
# ═════════════════════════════════════════════════════════════════════════════

def _safe(metrics: dict, *keys, default=np.nan):
    """Safely extract a nested value from metrics dict."""
    d = metrics
    for k in keys:
        if not isinstance(d, dict) or "error" in d:
            return default
        d = d.get(k, default)
    return d if d is not None else default


def _mean_valid(values: list[float], default=np.nan):
    """Mean over finite numeric values only."""
    valid = [v for v in values if pd.notna(v)]
    return float(np.mean(valid)) if valid else default


def aggregate_results_by_group(all_results: list[dict]) -> list[dict]:
    """
    Aggregate captures into one result per (platform, stream_type) group.
    This produces the required 2 stats per platform: dynamic and static.
    """
    grouped = defaultdict(list)
    for r in all_results:
        key = (r.get("platform", "unknown"), r.get("stream_type", "unknown"))
        grouped[key].append(r)

    aggregated = []

    for (platform, stream_type), group in sorted(grouped.items()):
        agg = {
            "label": f"{platform}_{stream_type}",
            "platform": platform,
            "stream_type": stream_type,
            "capture_count": len(group),
        }

        # RTT aggregation
        rtt_means = [_safe(r, "rtt", "mean_ms") for r in group]
        rtt_medians = [_safe(r, "rtt", "median_ms") for r in group]
        rtt_p95 = [_safe(r, "rtt", "p95_ms") for r in group]
        rtt_stds = [_safe(r, "rtt", "std_ms") for r in group]
        rtt_counts = [
            int(_safe(r, "rtt", "count", default=0))
            for r in group
            if pd.notna(_safe(r, "rtt", "count", default=np.nan))
        ]
        agg["rtt"] = {
            "count": int(sum(rtt_counts)),
            "mean_ms": _mean_valid(rtt_means),
            "median_ms": _mean_valid(rtt_medians),
            "p95_ms": _mean_valid(rtt_p95),
            "std_ms": _mean_valid(rtt_stds),
        }

        # Handshake RTT aggregation
        hs_means = [_safe(r, "handshake_rtt", "mean_ms") for r in group]
        hs_counts = [
            int(_safe(r, "handshake_rtt", "handshake_count", default=0))
            for r in group
            if pd.notna(_safe(r, "handshake_rtt", "handshake_count", default=np.nan))
        ]
        agg["handshake_rtt"] = {
            "handshake_count": int(sum(hs_counts)),
            "mean_ms": _mean_valid(hs_means),
        }

        # Jitter aggregation
        jitter_std = [_safe(r, "jitter", "std_ms") for r in group]
        jitter_mad = [_safe(r, "jitter", "mad_ms") for r in group]
        jitter_rfc = [_safe(r, "jitter", "rfc3550_jitter_ms") for r in group]
        jitter_p95 = [_safe(r, "jitter", "p95_delta_ms") for r in group]
        jitter_counts = [
            int(_safe(r, "jitter", "count", default=0))
            for r in group
            if pd.notna(_safe(r, "jitter", "count", default=np.nan))
        ]
        agg["jitter"] = {
            "count": int(sum(jitter_counts)),
            "std_ms": _mean_valid(jitter_std),
            "mad_ms": _mean_valid(jitter_mad),
            "rfc3550_jitter_ms": _mean_valid(jitter_rfc),
            "p95_delta_ms": _mean_valid(jitter_p95),
        }

        # Bitrate aggregation
        br_mean = [_safe(r, "bitrate", "mean_kbps") for r in group]
        br_std = [_safe(r, "bitrate", "std_kbps") for r in group]
        br_cv = [_safe(r, "bitrate", "cv") for r in group]
        br_p5 = [_safe(r, "bitrate", "p5_kbps") for r in group]
        br_p95 = [_safe(r, "bitrate", "p95_kbps") for r in group]
        br_windows = [
            int(_safe(r, "bitrate", "window_count", default=0))
            for r in group
            if pd.notna(_safe(r, "bitrate", "window_count", default=np.nan))
        ]
        agg["bitrate"] = {
            "window_count": int(sum(br_windows)),
            "mean_kbps": _mean_valid(br_mean),
            "std_kbps": _mean_valid(br_std),
            "cv": _mean_valid(br_cv),
            "p5_kbps": _mean_valid(br_p5),
            "p95_kbps": _mean_valid(br_p95),
        }

        # Protocol aggregation by summing bytes/packets across captures
        proto_bytes = defaultdict(int)
        proto_packets = defaultdict(int)
        quic_pcts = []
        for r in group:
            proto = r.get("protocols", {})
            for name in ("TCP", "UDP", "Other"):
                entry = proto.get(name)
                if isinstance(entry, dict):
                    proto_bytes[name] += int(entry.get("bytes", 0) or 0)
                    proto_packets[name] += int(entry.get("packets", 0) or 0)
            q = proto.get("quic_pct_bytes", np.nan)
            if pd.notna(q):
                quic_pcts.append(float(q))

        total_bytes = sum(proto_bytes.values())
        protocols = {"quic_pct_bytes": _mean_valid(quic_pcts, default=0.0)}
        for name in ("TCP", "UDP", "Other"):
            b = proto_bytes[name]
            p = proto_packets[name]
            pct = (b / total_bytes * 100.0) if total_bytes > 0 else 0.0
            protocols[name] = {"bytes": int(b), "packets": int(p), "pct": round(pct, 1)}
        agg["protocols"] = protocols

        aggregated.append(agg)

    return aggregated


def plot_comparison(all_results: list[dict], output_dir: str, time_series_source: list[dict] | None = None):
    """
    Generate a 2×2 comparison figure:
      [0,0] Mean RTT           [0,1] Jitter (std dev)
      [1,0] Average Bitrate    [1,1] Bitrate Stability (std dev)
    Plus a protocol stacked-bar chart.
    """
    if not all_results:
        print("[!] No results to plot.")
        return

    # ── Build a tidy summary DataFrame ───────────────────────────────────────
    rows = []
    for r in all_results:
        label = r.get("label", "?")
        rows.append({
            "label":        label,
            "platform":     r.get("platform", "unknown"),
            "stream_type":  r.get("stream_type", "unknown"),
            "rtt_mean":     _safe(r, "rtt", "mean_ms"),
            "rtt_p95":      _safe(r, "rtt", "p95_ms"),
            "jitter_std":   _safe(r, "jitter", "std_ms"),
            "jitter_rfc":   _safe(r, "jitter", "rfc3550_jitter_ms"),
            "br_mean":      _safe(r, "bitrate", "mean_kbps"),
            "br_std":       _safe(r, "bitrate", "std_kbps"),
            "br_cv":        _safe(r, "bitrate", "cv"),
            "tcp_pct":      _safe(r, "protocols", "TCP", "pct"),
            "udp_pct":      _safe(r, "protocols", "UDP", "pct"),
            "quic_pct":     _safe(r, "protocols", "quic_pct_bytes"),
        })
    df = pd.DataFrame(rows)

    colours = [PLATFORM_COLOURS.get(p, "#888888") for p in df["platform"]]
    x = np.arange(len(df))
    labels = df["label"].tolist()

    # ── Figure 1: 4-metric comparison ────────────────────────────────────────
    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    fig.suptitle("Live Streaming Platform — Network Performance Comparison", fontsize=14, fontweight="bold")

    metrics_cfg = [
        (axes[0, 0], "rtt_mean",   "Mean RTT (ms)",          "Lower is better"),
        (axes[0, 1], "jitter_std", "Jitter — Std Dev (ms)",  "Lower = more consistent arrival"),
        (axes[1, 0], "br_mean",    "Avg Bitrate (Kbps)",     "Higher = better quality"),
        (axes[1, 1], "br_std",     "Bitrate Std Dev (Kbps)", "Lower = more stable stream"),
    ]

    for ax, col, title, subtitle in metrics_cfg:
        vals = df[col].tolist()
        bars = ax.bar(x, vals, color=colours, edgecolor="white", linewidth=0.5, zorder=3)
        ax.set_title(f"{title}\n{subtitle}", fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
        ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:.0f}"))
        ax.grid(axis="y", alpha=0.3, zorder=0)
        ax.set_axisbelow(True)

        # Value labels on top of bars
        for bar, val in zip(bars, vals):
            if not np.isnan(val):
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.02,
                        f"{val:.1f}", ha="center", va="bottom", fontsize=7)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    out1 = os.path.join(output_dir, "comparison_metrics.png")
    fig.savefig(out1, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved: {out1}")

    # ── Figure 2: Protocol stacked bar ───────────────────────────────────────
    fig2, ax2 = plt.subplots(figsize=(10, 5))
    tcp_vals  = df["tcp_pct"].fillna(0).tolist()
    udp_vals  = df["udp_pct"].fillna(0).tolist()
    quic_vals = df["quic_pct"].fillna(0).tolist()
    # UDP-minus-QUIC
    pure_udp  = [max(0, u - q) for u, q in zip(udp_vals, quic_vals)]

    ax2.bar(x, tcp_vals,  label="TCP",       color="#2196F3", zorder=3)
    ax2.bar(x, pure_udp,  label="UDP",       color="#FF9800", bottom=tcp_vals, zorder=3)
    ax2.bar(x, quic_vals, label="QUIC/UDP",  color="#4CAF50",
            bottom=[t + u for t, u in zip(tcp_vals, pure_udp)], zorder=3)

    ax2.set_title("Protocol Distribution by Bytes (%)\n(QUIC = subset of UDP — indicates modern HTTP/3 usage)",
                  fontsize=11, fontweight="bold")
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax2.set_ylabel("Percentage of bytes (%)")
    ax2.set_ylim(0, 115)
    ax2.legend(loc="upper right")
    ax2.grid(axis="y", alpha=0.3, zorder=0)
    ax2.set_axisbelow(True)

    plt.tight_layout()
    out2 = os.path.join(output_dir, "comparison_protocols.png")
    fig2.savefig(out2, dpi=150, bbox_inches="tight")
    plt.close(fig2)
    print(f"[+] Saved: {out2}")

    # ── Figure 3: Bitrate time-series overlay ─────────────────────────────────
    source = time_series_source if time_series_source is not None else all_results

    fig3, axes3 = plt.subplots(1, 2, figsize=(14, 5), sharey=False)
    for stream_type, ax in zip(["dynamic", "static"], axes3):
        subset = [r for r in source if r.get("stream_type") == stream_type]
        for r in subset:
            br = r.get("bitrate", {})
            if "error" in br or not br.get("series_kbps"):
                continue
            colour = PLATFORM_COLOURS.get(r.get("platform", "unknown"), "#888888")
            t = np.array(br["series_index"]) * br.get("window_sec", 1)
            ax.plot(t, br["series_kbps"], label=r["platform"],
                    color=colour, linewidth=1.2, alpha=0.85)

        ax.set_title(f"Bitrate over Time — {stream_type.capitalize()} Streams", fontsize=11)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Throughput (Kbps)")
        ax.legend(loc="upper right", fontsize=8)
        ax.grid(alpha=0.3)

    plt.tight_layout()
    out3 = os.path.join(output_dir, "comparison_bitrate_timeseries.png")
    fig3.savefig(out3, dpi=150, bbox_inches="tight")
    plt.close(fig3)
    print(f"[+] Saved: {out3}")


# ═════════════════════════════════════════════════════════════════════════════
# 5.  CLI
# ═════════════════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        description="CS204 — Streaming platform packet-capture analyser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="mode", required=True)

    # ── auto mode: scan a results directory ──────────────────────────────────
    auto = sub.add_parser("auto", help="Discover and analyse all captures in a results dir")
    auto.add_argument("--results", default="../results", help="Results directory (default: ../results)")
    auto.add_argument("--no-plots", action="store_true", help="Skip chart generation")

    # ── single mode: analyse one capture by specifying CSV files directly ────
    single = sub.add_parser("single", help="Analyse a single capture set (explicit CSV paths)")
    single.add_argument("--rtt",       required=True)
    single.add_argument("--timing",    required=True)
    single.add_argument("--handshake", default="")
    single.add_argument("--protocols", default="")
    single.add_argument("--label",     default="Capture")
    single.add_argument("--results",   default="../results")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    os.makedirs(args.results, exist_ok=True)

    if args.mode == "single":
        files = {
            "rtt":       args.rtt,
            "timing":    args.timing,
            "handshake": args.handshake,
            "protocols": args.protocols,
        }
        r = analyse_capture(files, label=args.label)
        r["platform"]    = args.label.split("_")[0] if "_" in args.label else args.label
        r["stream_type"] = args.label.split("_")[1] if args.label.count("_") >= 1 else "unknown"
        print_summary(r)

        out_json = os.path.join(args.results, f"{args.label}_metrics.json")
        with open(out_json, "w") as f:
            # Remove non-serialisable series data before saving
            clean = {k: v for k, v in r.items() if k not in ("rtt",)}
            if "rtt" in r:
                clean["rtt"] = {k: v for k, v in r["rtt"].items() if k != "series_ms"}
            if "jitter" in r:
                clean["jitter"] = {k: v for k, v in r["jitter"].items() if k != "series_ms"}
            if "bitrate" in r:
                clean["bitrate"] = {k: v for k, v in r["bitrate"].items()
                                    if k not in ("series_kbps", "series_index")}
            json.dump(clean, f, indent=2)
        print(f"[+] Metrics JSON: {out_json}")

    elif args.mode == "auto":
        captures = discover_captures(args.results)
        if not captures:
            print(f"[!] No captures found in {args.results}")
            print("    Expected naming: <platform>_<stream_type>_<timestamp>_rtt.csv")
            sys.exit(1)

        print(f"[*] Found {len(captures)} capture(s):")
        for c in captures:
            print(f"    {c['platform']:12s}  {c['stream_type']:8s}  ({c['base']})")

        all_results = []
        for c in captures:
            label = f"{c['platform']}_{c['stream_type']}"
            r = analyse_capture(c["files"], label=label)
            r["platform"]    = c["platform"]
            r["stream_type"] = c["stream_type"]
            print_summary(r)
            all_results.append(r)

            out_json = os.path.join(args.results, f"{c['base']}_metrics.json")
            with open(out_json, "w") as f:
                clean = {}
                for key, val in r.items():
                    if isinstance(val, dict):
                        clean[key] = {k: v for k, v in val.items()
                                      if k not in ("series_ms", "series_kbps", "series_index", "values_ms")}
                    else:
                        clean[key] = val
                json.dump(clean, f, indent=2)

        # Aggregate runs so each platform has exactly two rows: dynamic + static
        aggregated_results = aggregate_results_by_group(all_results)

        # ── Comparison summary table ──────────────────────────────────────────
        print("\n" + "="*75)
        print(f"  {'Label':<30} {'Runs':>5} {'RTT(ms)':>9} {'Jitter(ms)':>11} {'Br(Kbps)':>10} {'BrStd':>8} {'Proto'}")
        print("="*75)
        for r in aggregated_results:
            rtt  = _safe(r, "rtt", "mean_ms")
            jit  = _safe(r, "jitter", "std_ms")
            br   = _safe(r, "bitrate", "mean_kbps")
            brs  = _safe(r, "bitrate", "std_kbps")
            runs = r.get("capture_count", 0)
            tcp  = _safe(r, "protocols", "TCP", "pct")
            udp  = _safe(r, "protocols", "UDP", "pct")
            quic = _safe(r, "protocols", "quic_pct_bytes")
            proto_str = f"TCP:{tcp:.0f}% UDP:{udp:.0f}% QUIC:{quic:.0f}%" \
                        if not any(np.isnan(v) for v in [tcp, udp, quic]) else "N/A"
            print(f"  {r['label']:<30} {runs:>5d} {rtt:>9.2f} {jit:>11.3f} {br:>10.1f} {brs:>8.1f}  {proto_str}")
        print("="*75)

        # Save grouped summary JSON used for platform-level comparisons
        grouped_json = os.path.join(args.results, "platform_stream_averages.json")
        with open(grouped_json, "w") as f:
            json.dump(aggregated_results, f, indent=2)
        print(f"[+] Grouped averages JSON: {grouped_json}")

        if not args.no_plots:
            print("\n[*] Generating comparison charts...")
            plot_comparison(aggregated_results, args.results, time_series_source=all_results)

        print(f"\n[+] Done. Results in: {args.results}")


if __name__ == "__main__":
    main()
