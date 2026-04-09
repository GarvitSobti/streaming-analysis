# Streaming Platform Network Analysis

CS204 networking project for measuring audience-side performance of live streaming platforms under different stream types and network conditions.

## What This Repo Does

1. Captures traffic for live streams with `tshark`.
2. Extracts packet-level fields from `.pcap` files into CSV files.
3. Computes RTT, handshake RTT, jitter, bitrate, and protocol split metrics.
4. Produces per-capture JSON summaries, grouped averages, and comparison plots.

## Project Structure

```
streaming-analysis/
├── orchestrate.py            # Interactive end-to-end workflow
├── capture/
│   ├── capture.sh            # Capture packets for one platform/session
│   ├── find_server.sh        # Quick server IP hint from active connections
│   ├── identify_servers.sh   # Sample traffic and rank likely CDN IPs
│   ├── run_experiment.sh     # Interactive runner for repeated experiments
│   └── stress_network.sh     # Apply/remove tc netem impairments
├── analysis/
│   ├── extract_metrics.sh    # Convert pcap -> *_rtt/timing/handshake/protocols.csv
│   └── analyze.py            # Compute metrics, JSON summaries, and plots
├── data/                     # Raw packet captures (*.pcap)
├── results/                  # CSV, JSON, and generated plots
├── requirements.txt
└── README.md
```

## Metrics

- RTT from TCP ACK timing.
- Handshake RTT from SYN/SYN-ACK pairs.
- Jitter from inter-arrival variation on large frames.
- Average bitrate over 1-second windows.
- Bitrate stability using standard deviation and coefficient of variation.
- Protocol split by bytes and packets, including TCP, UDP, and QUIC detection.

## Requirements

### System packages on Linux

```bash
sudo apt update
sudo apt install -y tshark wireshark-common iproute2 dnsutils
```

Notes:
- `tshark` and `capinfos` are used by the capture and extraction scripts.
- `tc` from `iproute2` is required for `stress_network.sh`.
- `host` from `dnsutils` is used by `identify_servers.sh`.

### Python dependencies

```bash
pip install -r requirements.txt
```

The analysis scripts use `numpy`, `pandas`, and `matplotlib`.

## Quick Start

### 1) Optional: identify the CDN server IP

While the stream is already playing in your browser:

```bash
bash capture/identify_servers.sh 30
```

If you want a faster manual hint:

```bash
bash capture/find_server.sh
```

### 2) Capture traffic

```bash
bash capture/capture.sh <platform> <server_ip> [duration_seconds] [stream_type]
```

Supported platforms:

- `youtube`
- `twitch`
- `tiktok`
- `instagram`

Supported stream types:

- `dynamic`
- `static`

Examples:

```bash
bash capture/capture.sh youtube 142.250.1.1 300 dynamic
bash capture/capture.sh twitch 151.101.1.1 300 static
bash capture/capture.sh tiktok "" 300 dynamic
```

If the server IP is unknown, pass an empty string and the script captures all TCP/UDP traffic.

The capture is saved in `data/` as:

`<platform>_<stream_type>_<timestamp>.pcap`

### 3) Extract CSV metrics from a pcap

```bash
bash analysis/extract_metrics.sh data/<capture>.pcap results
```

This produces:

- `<name>_rtt.csv`
- `<name>_timing.csv`
- `<name>_handshake.csv`
- `<name>_protocols.csv`

### 4) Analyze the extracted metrics

Single capture mode:

```bash
python analysis/analyze.py single \
  --rtt results/<name>_rtt.csv \
  --timing results/<name>_timing.csv \
  --handshake results/<name>_handshake.csv \
  --protocols results/<name>_protocols.csv \
  --label youtube_dynamic \
  --results results
```

Auto mode, which discovers every capture set in `results/`:

```bash
python analysis/analyze.py auto --results results
```

Auto mode writes:

- Per-capture `*_metrics.json`
- `results/platform_stream_averages.json`
- `results/comparison_metrics.png`
- `results/comparison_protocols.png`
- `results/comparison_bitrate_timeseries.png`

## End-to-End Orchestration

For a guided workflow, use the Python orchestrator:

```bash
python orchestrate.py
```

It provides menu options for single capture, batch capture, re-analysis of existing results, and CDN server identification.

Useful direct modes:

```bash
python orchestrate.py --batch
python orchestrate.py --analyze-only
```

For repeated scripted runs, you can also use:

```bash
bash capture/run_experiment.sh
```

Before using `run_experiment.sh`, edit its config section to set run counts, stream types, duration, and any known platform IPs. It logs each run to `results/experiment_log_*.txt`.

## Optional Network Impairment

Use `tc netem` to apply or clear network conditions:

```bash
bash capture/stress_network.sh status
bash capture/stress_network.sh loss5
bash capture/stress_network.sh delay100
bash capture/stress_network.sh combined
bash capture/stress_network.sh reset
```

Supported conditions:

- `baseline`
- `loss5`
- `delay100`
- `combined`
- `reset`
- `status`

## Suggested Experimental Protocol

1. Close all non-essential apps.
2. Use a wired connection where possible.
3. Select a 1080p stream that has been live for at least 30 minutes.
4. Let the stream stabilize before capturing.
5. Capture for a fixed duration across all runs.
6. Repeat for both stream types.
7. Repeat multiple times per platform for statistical validity.

## Limitations

- Single geographic measurement point.
- CDN edge nodes vary between runs, so repeated captures may hit different servers.
- Ads can create separate connections, which can affect filtering and interpretation.
- Encrypted streams limit deep packet inspection, so several metrics are frame-level rather than payload-level.

## Test Videos
Dynamic video: https://www.youtube.com/watch?v=O3zmfntbSr8&t=600s
Static video: https://www.youtube.com/live/OChp0jbyEbI?si=TYy555bRWdEuXad-&t=4200