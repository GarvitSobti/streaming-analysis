# Streaming Platform Network Analysis

**CS204 Computer Networking**

Comparing live streaming platform performance (YouTube Live, TikTok Live, Instagram Live, Twitch) from the **audience side**, across two stream types:
- **Dynamic streams** (gaming content — high motion, variable bitrate)
- **Static streams** (talk shows / live chats — low motion, stable bitrate)

## Research Question

> Which live video streaming platform has the best network performance?

## Metrics

| Metric | Definition | Tool |
|---|---|---|
| RTT | SYN → SYN-ACK time (TCP handshake) | tshark / Wireshark |
| Inter-packet Jitter | Variance of frame inter-arrival times | tshark → Python |
| Average Bitrate | Mean bits/second over 3-minute window | tshark → Python |
| Bitrate Std Dev | Stability of the stream | tshark → Python |
| Protocol | Transport layer protocol (TCP/QUIC/WebRTC) | Wireshark |

## Platforms

| Platform | Known Protocol | CDN |
|---|---|---|
| YouTube Live | QUIC (HTTP/3) or HLS over TLS | Google |
| TikTok Live | WebRTC / HLS | Akamai / ByteDance |
| Instagram Live | WebRTC | Meta |
| Twitch | HLS over TCP | AWS CloudFront |

## Project Structure

```
streaming-analysis/
├── capture/
│   ├── capture.sh            # headless tshark capture (5 min)
│   ├── find_server.sh        # identify CDN IP via ss
│   └── stress_test.sh        # tc/netem packet loss & jitter injection
├── analysis/
│   ├── extract_metrics.py    # parse .pcap → RTT, jitter, bitrate CSV
│   ├── compare_platforms.py  # aggregate comparison across all platforms
│   └── visualize.py          # generate bar charts & time-series plots
├── data/                     # .pcap files (gitignored, too large)
├── results/                  # output CSVs and plots (gitignored)
└── requirements.txt
```

## Setup

### Linux (required)
```bash
sudo apt update && sudo apt install tshark iproute2 curl
pip install -r requirements.txt
```

### macOS (limited — no tc/netem)
```bash
brew install wireshark
pip install -r requirements.txt
```

## Workflow

### Phase 1: Capture

```bash
# 1. Find which network interface you're on
ip link show

# 2. Open browser, start the stream, then identify the CDN server IP
bash capture/find_server.sh

# 3. Run a 5-minute capture for each platform
bash capture/capture.sh youtube eth0
bash capture/capture.sh tiktok eth0
bash capture/capture.sh instagram eth0
bash capture/capture.sh twitch eth0
```

### Phase 2: Stress Test (Optional)

```bash
# Simulate bad network: 100ms latency + 5% packet loss
bash capture/stress_test.sh add
# ... run a capture ...
bash capture/stress_test.sh remove
```

### Phase 3: Analysis

```bash
# Extract RTT, jitter, bitrate from all pcap files
python analysis/extract_metrics.py

# Compare all platforms
python analysis/compare_platforms.py

# Generate plots
python analysis/visualize.py
```

## Experiment Protocol

1. Close all non-essential apps (Spotify, Discord, updates)
2. Use a wired connection where possible
3. Select a **1080p stream** that has been live for >30 minutes
4. Let stream run for **3 minutes** in steady state before capturing
5. Capture for exactly **5 minutes**
6. Repeat for both stream types (gaming vs talk/chat)
7. Repeat 3 times per platform per stream type for statistical validity

## Limitations

- Single geographic measurement point
- CDN edge node varies — re-run on different days may hit different servers
- Ads create separate connections — filter by `frame.len > 1200` to isolate video
- Encrypted streams (QUIC/TLS) limit deep packet inspection; use frame-level metrics


## Links to videos
Dynamic video: https://www.youtube.com/watch?v=O3zmfntbSr8&t=600s
Static video: https://www.youtube.com/live/OChp0jbyEbI?si=TYy555bRWdEuXad-&t=4200


## Links to platforms
Twitch: https://www.twitch.tv/raylight0331
Youtube: [rtmp://a.rtmp.youtube.com/live2](https://youtube.com/live/Dvm-M6AP9Zg?feature=share)