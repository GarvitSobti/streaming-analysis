#!/usr/bin/env python3
"""
orchestrate.py — Interactive experiment orchestrator
=====================================================
CS204 Computer Networks — Streaming Platform Analysis

A guided, interactive tool that walks you through:
  1. Select platform & stream type
  2. (Optional) Identify the CDN server IP
  3. Start packet capture — go open the video NOW
  4. Live countdown while capture runs
  5. Auto-extract metrics from the .pcap
  6. Auto-analyse and generate charts

Usage:
    python orchestrate.py                  # interactive mode
    python orchestrate.py --batch          # run all combos back-to-back
    python orchestrate.py --analyze-only   # skip capture, just re-analyze results/
"""

import argparse
import glob
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# ─── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).resolve().parent
CAPTURE_SH   = SCRIPT_DIR / "capture" / "capture.sh"
ID_SERVERS   = SCRIPT_DIR / "capture" / "identify_servers.sh"
EXTRACT_SH   = SCRIPT_DIR / "analysis" / "extract_metrics.sh"
ANALYZE_PY   = SCRIPT_DIR / "analysis" / "analyze.py"
DATA_DIR     = SCRIPT_DIR / "data"
RESULTS_DIR  = SCRIPT_DIR / "results"

# ─── ANSI colours ────────────────────────────────────────────────────────────
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
RESET   = "\033[0m"

PLATFORM_COLOURS = {
    "youtube":   "\033[91m",   # red
    "twitch":    "\033[95m",   # purple
    "tiktok":    "\033[97m",   # white
    "instagram": "\033[95m",   # magenta
}

# ─── Config ──────────────────────────────────────────────────────────────────
PLATFORMS    = ["youtube", "twitch", "tiktok", "instagram"]
STREAM_TYPES = ["dynamic", "static"]
DEFAULT_DURATION = 180  # seconds (3 minutes)

STREAM_TYPE_DESC = {
    "dynamic": "🎮  Gaming / action stream (fast movement, high bitrate variation)",
    "static":  "🗣️  Chat / talking-head stream (mostly still, low bitrate variation)",
}

PLATFORM_HINTS = {
    "youtube":   "Open YouTube Live → pick a stream → set quality to 1080p",
    "twitch":    "Open Twitch → pick a live channel → set quality to 1080p",
    "tiktok":    "Open TikTok Live → pick a LIVE stream",
    "instagram": "Open Instagram → go to a LIVE broadcast",
}


# ═════════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═════════════════════════════════════════════════════════════════════════════

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗
║         CS204 — Streaming Platform Network Analysis          ║
║                   Experiment Orchestrator                     ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def section(title):
    width = 58
    print(f"\n{BLUE}{BOLD}┌{'─' * width}┐{RESET}")
    print(f"{BLUE}{BOLD}│  {title:<{width - 2}}│{RESET}")
    print(f"{BLUE}{BOLD}└{'─' * width}┘{RESET}")


def step(num, text):
    print(f"\n  {CYAN}{BOLD}[Step {num}]{RESET}  {text}")


def info(text):
    print(f"  {DIM}ℹ  {text}{RESET}")


def success(text):
    print(f"  {GREEN}✔  {text}{RESET}")


def warn(text):
    print(f"  {YELLOW}⚠  {text}{RESET}")


def error(text):
    print(f"  {RED}✘  {text}{RESET}")


def prompt(text, default=None):
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {MAGENTA}▸{RESET}  {text}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return val if val else default


def prompt_choice(text, options, default=None):
    """Show numbered options and return the selected value."""
    print(f"\n  {text}")
    for i, opt in enumerate(options, 1):
        marker = f" {DIM}(default){RESET}" if opt == default else ""
        print(f"    {CYAN}{i}{RESET}) {opt}{marker}")
    while True:
        raw = prompt("Enter number", str(options.index(default) + 1) if default else None)
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx]
        except (ValueError, TypeError):
            pass
        warn(f"Please enter a number between 1 and {len(options)}")


def prompt_yn(text, default=True):
    hint = "Y/n" if default else "y/N"
    raw = prompt(f"{text} ({hint})", "y" if default else "n")
    return raw.lower() in ("y", "yes", "")


def prompt_non_negative_int(text, default=0):
    """Prompt until user provides a non-negative integer."""
    while True:
        raw = prompt(text, str(default))
        try:
            value = int(raw)
            if value >= 0:
                return value
        except (TypeError, ValueError):
            pass
        warn("Please enter a whole number >= 0")


def countdown_timer(total_seconds, label="Capturing"):
    """
    Live countdown with a progress bar.
    Shows elapsed/remaining time. User can Ctrl+C to stop early.
    """
    bar_width = 40
    start = time.time()

    try:
        while True:
            elapsed = time.time() - start
            remaining = max(0, total_seconds - elapsed)

            if elapsed >= total_seconds:
                break

            pct = elapsed / total_seconds
            filled = int(bar_width * pct)
            bar = f"{'█' * filled}{'░' * (bar_width - filled)}"

            elapsed_str   = time.strftime("%M:%S", time.gmtime(elapsed))
            remaining_str = time.strftime("%M:%S", time.gmtime(remaining))

            line = (
                f"\r  {CYAN}⏱{RESET}  {label}  "
                f"{BOLD}{bar}{RESET}  "
                f"{elapsed_str} / {time.strftime('%M:%S', time.gmtime(total_seconds))}  "
                f"{DIM}({remaining_str} left){RESET}  "
            )
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.5)

    except KeyboardInterrupt:
        pass

    # Final state
    bar = f"{'█' * bar_width}"
    final_elapsed = time.strftime("%M:%S", time.gmtime(min(time.time() - start, total_seconds)))
    sys.stdout.write(
        f"\r  {GREEN}✔{RESET}  {label}  "
        f"{GREEN}{BOLD}{bar}{RESET}  "
        f"{final_elapsed} / {time.strftime('%M:%S', time.gmtime(total_seconds))}  "
        f"{GREEN}DONE{RESET}          \n"
    )
    sys.stdout.flush()


def run_shell(cmd, cwd=None, stream_output=False):
    """Run a shell command. Returns (returncode, stdout, stderr)."""
    if stream_output:
        proc = subprocess.Popen(
            cmd, shell=True, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        output_lines = []
        for line in proc.stdout:
            print(f"    {DIM}{line.rstrip()}{RESET}")
            output_lines.append(line)
        proc.wait()
        return proc.returncode, "".join(output_lines), ""
    else:
        result = subprocess.run(
            cmd, shell=True, cwd=cwd,
            capture_output=True, text=True,
        )
        return result.returncode, result.stdout, result.stderr


def find_latest_pcap(platform, stream_type):
    """Find the most recently created .pcap for a platform/stream_type combo."""
    pattern = str(DATA_DIR / f"{platform}_{stream_type}_*.pcap")
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


# ═════════════════════════════════════════════════════════════════════════════
# Core workflow stages
# ═════════════════════════════════════════════════════════════════════════════

def stage_identify_servers(duration=30):
    """Run identify_servers.sh to find the CDN server IP."""
    section("Server Identification")
    info("Sniffing traffic to find which IP is serving the video stream...")
    info(f"Make sure the stream is ALREADY PLAYING in your browser!")
    print()

    cmd = f"bash {ID_SERVERS} {duration}"
    rc, out, err = run_shell(cmd, cwd=str(SCRIPT_DIR), stream_output=True)

    if rc != 0:
        error("Server identification failed (see output above)")
        return None

    server_ip = prompt("Enter the CDN server IP from above (or press Enter to skip)", "")
    return server_ip if server_ip else None


def stage_capture(platform, stream_type, server_ip="", duration=DEFAULT_DURATION):
    """
    Start tshark capture, show countdown, return path to .pcap.
    The capture runs as a subprocess while we show a progress bar.
    """
    section(f"Packet Capture — {platform.upper()} / {stream_type}")

    colour = PLATFORM_COLOURS.get(platform, "")
    print(f"""
  {colour}{BOLD}Platform   :{RESET} {platform}
  {colour}{BOLD}Stream type:{RESET} {stream_type}  — {STREAM_TYPE_DESC[stream_type]}
  {BOLD}Duration   :{RESET} {duration}s ({duration // 60}m {duration % 60}s)
  {BOLD}Server IP  :{RESET} {server_ip if server_ip else '(all traffic)'}
""")

    # Build the capture command
    ip_arg = f'"{server_ip}"' if server_ip else '""'
    cmd = f'bash "{CAPTURE_SH}" {platform} {ip_arg} {duration} {stream_type}'

    print(f"  {YELLOW}{BOLD}{'━' * 58}{RESET}")
    print(f"  {YELLOW}{BOLD}  🎬  GO OPEN THE VIDEO NOW!{RESET}")
    print(f"  {YELLOW}  {PLATFORM_HINTS.get(platform, 'Open the platform and start a live stream')}{RESET}")
    print(f"  {YELLOW}{BOLD}{'━' * 58}{RESET}")
    print()

    # Countdown before capture starts (gives user time to switch to browser)
    pre_wait = 10
    info(f"Capture starts in {pre_wait} seconds — switch to your browser!")
    for i in range(pre_wait, 0, -1):
        sys.stdout.write(f"\r  {CYAN}⏳  Starting in {i}s...{RESET}  ")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write(f"\r  {GREEN}🚀  Capture started!{RESET}              \n\n")

    # Launch capture as background process
    proc = subprocess.Popen(
        cmd, shell=True, cwd=str(SCRIPT_DIR),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    # Show live countdown while capture runs
    countdown_timer(duration, label=f"Capturing {platform}/{stream_type}")

    # Wait for tshark to actually finish (may take a second after duration)
    proc.wait(timeout=30)

    # Print capture output
    output = proc.stdout.read()
    if output.strip():
        print(f"\n  {DIM}── capture.sh output ──{RESET}")
        for line in output.strip().split("\n"):
            print(f"    {DIM}{line}{RESET}")

    # Find the pcap file
    pcap_path = find_latest_pcap(platform, stream_type)
    if pcap_path:
        size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
        success(f"Capture saved: {os.path.basename(pcap_path)}  ({size_mb:.1f} MB)")
        return pcap_path
    else:
        error("No .pcap file found after capture!")
        return None


def stage_extract(pcap_path):
    """Run extract_metrics.sh on a .pcap file."""
    section("Metric Extraction")
    info(f"Extracting CSV metrics from: {os.path.basename(pcap_path)}")
    print()

    cmd = f'bash "{EXTRACT_SH}" "{pcap_path}"'
    rc, out, err = run_shell(cmd, cwd=str(SCRIPT_DIR), stream_output=True)

    if rc != 0:
        error("Extraction failed!")
        if err:
            print(f"    {RED}{err}{RESET}")
        return False

    success("All CSVs extracted successfully")
    return True


def stage_analyze():
    """Run analyze.py in auto mode on all results."""
    section("Analysis & Visualization")
    info(f"Analyzing all captures in {RESULTS_DIR}...")
    print()

    cmd = f'python3 "{ANALYZE_PY}" auto --results "{RESULTS_DIR}"'
    rc, out, err = run_shell(cmd, cwd=str(SCRIPT_DIR), stream_output=True)

    if rc != 0:
        # Try with 'python' instead of 'python3' (Windows compat)
        cmd2 = f'python "{ANALYZE_PY}" auto --results "{RESULTS_DIR}"'
        rc, out, err = run_shell(cmd2, cwd=str(SCRIPT_DIR), stream_output=True)

    if rc != 0:
        error("Analysis failed!")
        return False

    # List generated files
    pngs = glob.glob(str(RESULTS_DIR / "*.png"))
    jsons = glob.glob(str(RESULTS_DIR / "*.json"))
    if pngs:
        print()
        success("Generated charts:")
        for p in sorted(pngs):
            print(f"    📊  {os.path.basename(p)}")
    if jsons:
        success("Generated JSON reports:")
        for j in sorted(jsons):
            print(f"    📄  {os.path.basename(j)}")

    return True


# ═════════════════════════════════════════════════════════════════════════════
# Main interactive flow
# ═════════════════════════════════════════════════════════════════════════════

def interactive_single():
    """Guide the user through a single capture → extract → analyze cycle."""

    # ── Step 1: Choose platform ──
    step(1, "Choose a platform")
    platform = prompt_choice("Which platform are you capturing?", PLATFORMS, default="youtube")

    # ── Step 2: Choose stream type ──
    step(2, "Choose stream type")
    for st in STREAM_TYPES:
        print(f"    {STREAM_TYPE_DESC[st]}")
    stream_type = prompt_choice("Which stream type?", STREAM_TYPES, default="dynamic")

    # ── Step 3: Capture duration ──
    step(3, "Capture duration")
    dur_str = prompt("Duration in seconds", str(DEFAULT_DURATION))
    try:
        duration = int(dur_str)
    except ValueError:
        duration = DEFAULT_DURATION
        warn(f"Invalid input — using default: {duration}s")

    # ── Step 4: Server identification (optional) ──
    step(4, "CDN Server identification (optional)")
    info("If you already know the CDN IP, enter it below.")
    info("Otherwise, you can run automatic identification (requires the stream to be playing).")

    server_ip = ""
    choice = prompt_choice("How to set the server IP?", [
        "Skip — capture all traffic (works, but noisier)",
        "Enter IP manually",
        "Auto-detect (runs identify_servers.sh — stream must be playing)",
    ], default="Skip — capture all traffic (works, but noisier)")

    if "Enter" in choice:
        server_ip = prompt("Enter CDN server IP", "") or ""
    elif "Auto" in choice:
        server_ip = stage_identify_servers() or ""

    # ── Step 5: Capture ──
    step(5, "Packet capture")
    pcap_path = stage_capture(platform, stream_type, server_ip, duration)

    if not pcap_path:
        error("Capture failed — aborting.")
        return

    # ── Step 6: Extract ──
    step(6, "Extract metrics")
    if not stage_extract(pcap_path):
        error("Extraction failed — you can retry manually:")
        info(f"  bash analysis/extract_metrics.sh {pcap_path}")
        return

    # ── Step 7: Analyze ──
    step(7, "Analyze results")
    if prompt_yn("Run full analysis now?"):
        stage_analyze()

    # ── Done ──
    print(f"""
{GREEN}{BOLD}╔══════════════════════════════════════════════════════════════╗
║                     ✔  ALL DONE!                             ║
╚══════════════════════════════════════════════════════════════╝{RESET}

  {BOLD}Pcap file :{RESET} {pcap_path}
  {BOLD}CSVs in   :{RESET} {RESULTS_DIR}/
  {BOLD}Charts in :{RESET} {RESULTS_DIR}/

  {DIM}To re-analyze all captures:{RESET}
    python analysis/analyze.py auto --results results/

  {DIM}To run another capture, just run this script again!{RESET}
""")


def interactive_batch():
    """Run captures for ALL platform × stream_type combos, back to back."""
    section("Batch Mode — All Platforms × Stream Types")

    combos = [(p, st) for p in PLATFORMS for st in STREAM_TYPES]
    runs_per_combo = {}

    print(f"\n  Platform/stream combinations:")
    for i, (p, st) in enumerate(combos, 1):
        print(f"    {i:2d}. {p:<12s}  {st}")

    print("\n  Enter how many runs you want for each combination (0 = skip).")
    for p, st in combos:
        runs_per_combo[(p, st)] = prompt_non_negative_int(f"Runs for {p}/{st}", default=1)

    run_plan = []
    for p, st in combos:
        count = runs_per_combo[(p, st)]
        for run_idx in range(1, count + 1):
            run_plan.append((p, st, run_idx, count))

    total = len(run_plan)
    if total == 0:
        warn("All combinations were set to 0 runs. Nothing to do.")
        return

    print(f"\n  This will run {BOLD}{total} captures{RESET} in total:")
    for p, st in combos:
        count = runs_per_combo[(p, st)]
        print(f"    - {p:<12s}  {st:<7s}  x{count}")

    duration_str = prompt("Duration per capture (seconds)", str(DEFAULT_DURATION))
    try:
        duration = int(duration_str)
    except ValueError:
        duration = DEFAULT_DURATION

    total_time = total * (duration + 15)  # +15 for pre-wait and extraction
    info(f"Estimated total time: ~{total_time // 60} minutes")

    if not prompt_yn("Proceed?"):
        info("Cancelled.")
        return

    completed = []
    skipped = []

    for i, (platform, stream_type, run_idx, run_total) in enumerate(run_plan, 1):
        print(f"\n{'═' * 60}")
        print(f"  {BOLD}Run {i} / {total}{RESET}  —  {platform} / {stream_type}  ({run_idx}/{run_total})")
        print(f"{'═' * 60}")

        if not prompt_yn(f"Ready to capture {platform}/{stream_type} ({run_idx}/{run_total})?"):
            warn(f"Skipped {platform}/{stream_type} ({run_idx}/{run_total})")
            skipped.append((platform, stream_type, run_idx, run_total))
            continue

        pcap_path = stage_capture(platform, stream_type, "", duration)
        if pcap_path:
            stage_extract(pcap_path)
            completed.append((platform, stream_type, run_idx, run_total, pcap_path))
        else:
            error(f"Capture failed for {platform}/{stream_type} ({run_idx}/{run_total})")
            skipped.append((platform, stream_type, run_idx, run_total))

    # Final analysis across everything
    if completed:
        section("Final Analysis — All Captures")
        stage_analyze()

    # Summary
    print(f"\n{'═' * 60}")
    print(f"  {BOLD}Batch Summary{RESET}")
    print(f"{'═' * 60}")
    print(f"  {GREEN}Completed: {len(completed)}{RESET}")
    for p, st, run_idx, run_total, path in completed:
        print(f"    ✔  {p}/{st} ({run_idx}/{run_total})  →  {os.path.basename(path)}")
    if skipped:
        print(f"  {YELLOW}Skipped:   {len(skipped)}{RESET}")
        for p, st, run_idx, run_total in skipped:
            print(f"    ⊘  {p}/{st} ({run_idx}/{run_total})")
    print()


def analyze_only():
    """Just re-run analysis on existing results."""
    banner()
    section("Re-Analysis Mode")
    info("Skipping capture — analyzing existing CSVs in results/")
    stage_analyze()


# ═════════════════════════════════════════════════════════════════════════════
# Main menu
# ═════════════════════════════════════════════════════════════════════════════

def main_menu():
    """Top-level interactive menu."""
    banner()

    # Check for existing results
    existing_csvs = glob.glob(str(RESULTS_DIR / "*_rtt.csv"))
    existing_pcaps = glob.glob(str(DATA_DIR / "*.pcap"))

    if existing_csvs or existing_pcaps:
        info(f"Found {len(existing_pcaps)} existing .pcap file(s) and {len(existing_csvs)} CSV set(s)")

    mode = prompt_choice(
        f"{BOLD}What would you like to do?{RESET}",
        [
            "🎯  Single capture (one platform, guided step-by-step)",
            "📋  Batch capture (all platforms × stream types)",
            "📊  Re-analyze existing results (no capture)",
            "🔍  Identify CDN servers (run while stream is playing)",
            "❌  Exit",
        ],
        default="🎯  Single capture (one platform, guided step-by-step)",
    )

    if "Single" in mode:
        interactive_single()
    elif "Batch" in mode:
        interactive_batch()
    elif "Re-analyze" in mode:
        analyze_only()
    elif "Identify" in mode:
        stage_identify_servers()
    elif "Exit" in mode:
        info("Goodbye!")
        sys.exit(0)

    # Offer to continue
    print()
    if prompt_yn("Run another task?"):
        main_menu()


def main():
    parser = argparse.ArgumentParser(
        description="CS204 — Interactive experiment orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--batch", action="store_true",
                        help="Jump straight to batch mode (all platforms)")
    parser.add_argument("--analyze-only", action="store_true",
                        help="Skip capture — just re-analyze existing results")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help=f"Capture duration in seconds (default: {DEFAULT_DURATION})")
    args = parser.parse_args()

    # Ensure output dirs exist
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.analyze_only:
        analyze_only()
    elif args.batch:
        banner()
        interactive_batch()
    else:
        main_menu()


if __name__ == "__main__":
    main()
