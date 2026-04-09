#!/bin/bash
# =============================================================================
# extract_metrics.sh — Dump pcap fields to CSV via tshark
# CS204 Computer Networks Project
#
# Usage:
#   ./extract_metrics.sh <path/to/capture.pcap> [output_dir]
#
# Produces 4 CSV files per pcap:
#   <name>_rtt.csv        — TCP ACK RTT per packet (for latency analysis)
#   <name>_timing.csv     — Frame arrival times + sizes (for jitter + bitrate)
#   <name>_handshake.csv  — SYN/SYN-ACK pairs (for connection-establishment RTT)
#   <name>_protocols.csv  — Protocol breakdown per packet
# =============================================================================

set -euo pipefail

PCAP_FILE=${1:?"Usage: $0 <pcap_file> [output_dir]"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR=${2:-"${SCRIPT_DIR}/../results"}
BASENAME=$(basename "$PCAP_FILE" .pcap)

if [[ ! -f "$PCAP_FILE" ]]; then
    echo "[!] File not found: $PCAP_FILE"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] Extracting from: $PCAP_FILE"
echo "    Output dir: $OUTPUT_DIR"
echo ""

# ── 1. TCP ACK RTT ────────────────────────────────────────────────────────────
# tcp.analysis.ack_rtt = time from a data segment to its ACK
# This gives us per-packet RTT across the entire session.
echo "[1/4] TCP ACK RTT..."
tshark -r "$PCAP_FILE" \
       -T fields \
       -e frame.number \
       -e frame.time_relative \
       -e ip.src \
       -e ip.dst \
       -e tcp.analysis.ack_rtt \
       -Y "tcp.analysis.ack_rtt" \
       -E header=y \
       -E separator=, \
       2>/dev/null \
       > "${OUTPUT_DIR}/${BASENAME}_rtt.csv"
echo "    -> ${OUTPUT_DIR}/${BASENAME}_rtt.csv  ($(wc -l < "${OUTPUT_DIR}/${BASENAME}_rtt.csv") rows)"

# ── 2. Frame timing (jitter + bitrate raw material) ─────────────────────────
# frame.time_delta = inter-arrival time between consecutive packets
# frame.len = frame size in bytes
# Filter: large frames only (>500 bytes) to focus on video payload
echo "[2/4] Frame timing (inter-arrival + sizes)..."
tshark -r "$PCAP_FILE" \
       -T fields \
       -e frame.number \
       -e frame.time_epoch \
       -e frame.time_relative \
       -e frame.time_delta \
       -e frame.len \
       -e ip.src \
       -e ip.dst \
       -e ip.proto \
       -E header=y \
       -E separator=, \
       2>/dev/null \
       > "${OUTPUT_DIR}/${BASENAME}_timing.csv"
echo "    -> ${OUTPUT_DIR}/${BASENAME}_timing.csv  ($(wc -l < "${OUTPUT_DIR}/${BASENAME}_timing.csv") rows)"

# ── 3. TCP handshake (connection-establishment RTT) ──────────────────────────
# SYN and SYN-ACK timestamps let us calculate the very first RTT
echo "[3/4] TCP handshake packets..."
tshark -r "$PCAP_FILE" \
       -T fields \
       -e frame.number \
       -e frame.time_relative \
       -e ip.src \
       -e ip.dst \
       -e tcp.srcport \
       -e tcp.dstport \
       -e tcp.flags \
       -e tcp.flags.syn \
       -e tcp.flags.ack \
       -Y "tcp.flags.syn == 1" \
       -E header=y \
       -E separator=, \
       2>/dev/null \
       > "${OUTPUT_DIR}/${BASENAME}_handshake.csv"
echo "    -> ${OUTPUT_DIR}/${BASENAME}_handshake.csv  ($(wc -l < "${OUTPUT_DIR}/${BASENAME}_handshake.csv") rows)"

# ── 4. Protocol distribution ─────────────────────────────────────────────────
echo "[4/4] Protocol distribution..."
tshark -r "$PCAP_FILE" \
       -T fields \
       -e frame.number \
       -e frame.time_relative \
       -e frame.len \
       -e ip.proto \
       -e frame.protocols \
       -E header=y \
       -E separator=, \
       2>/dev/null \
       > "${OUTPUT_DIR}/${BASENAME}_protocols.csv"
echo "    -> ${OUTPUT_DIR}/${BASENAME}_protocols.csv  ($(wc -l < "${OUTPUT_DIR}/${BASENAME}_protocols.csv") rows)"

# ── Summary stats via tshark capinfos ────────────────────────────────────────
echo ""
echo "=== Capture Summary (capinfos) ==="
capinfos "$PCAP_FILE" 2>/dev/null || echo "(capinfos not available)"

echo ""
echo "[+] All CSVs ready. Run: python analyze.py"
