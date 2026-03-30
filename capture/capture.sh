#!/bin/bash
# =============================================================================
# capture.sh — Automated tshark packet capture per streaming platform
# CS204 Computer Networks Project
#
# Usage:
#   ./capture.sh <platform> <server_ip> [duration] [stream_type]
#
# Examples:
#   ./capture.sh youtube  142.250.1.1  300 dynamic
#   ./capture.sh twitch   151.101.1.1  300 static
#   ./capture.sh tiktok   "" 300 dynamic   # capture all traffic if IP unknown
#
# stream_type: "dynamic" (games) | "static" (chats/talking heads)
# duration:    seconds to capture (default 300 = 5 minutes)
# =============================================================================

set -euo pipefail

PLATFORM=${1:?"Usage: $0 <platform> <server_ip> [duration] [stream_type]"}
SERVER_IP=${2:-""}
DURATION=${3:-300}
STREAM_TYPE=${4:-"dynamic"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
CAPTURE_FILE="${DATA_DIR}/${PLATFORM}_${STREAM_TYPE}_${TIMESTAMP}.pcap"

# Auto-detect default network interface
INTERFACE=$(ip route | awk '/^default/ {print $5; exit}')

mkdir -p "$DATA_DIR"

echo "============================================"
echo " Streaming Analysis — Packet Capture"
echo "============================================"
echo " Platform    : $PLATFORM"
echo " Stream type : $STREAM_TYPE"
echo " Interface   : $INTERFACE"
echo " Server IP   : ${SERVER_IP:-"(all traffic)"}"
echo " Duration    : ${DURATION}s"
echo " Output      : $CAPTURE_FILE"
echo "============================================"
echo ""
echo "[*] Waiting 3 seconds — open the stream NOW in your browser..."
sleep 3

echo "[*] Starting capture... (Ctrl+C to stop early)"

if [ -z "$SERVER_IP" ]; then
    # Capture all TCP/UDP if no server IP provided
    tshark -i "$INTERFACE" \
           -f "tcp or udp" \
           -a duration:"$DURATION" \
           -w "$CAPTURE_FILE" \
           2>&1 | grep -v "^Capturing"
else
    # Targeted capture — much cleaner data
    tshark -i "$INTERFACE" \
           -f "host ${SERVER_IP} and (tcp or udp)" \
           -a duration:"$DURATION" \
           -w "$CAPTURE_FILE" \
           2>&1 | grep -v "^Capturing"
fi

FILESIZE=$(du -sh "$CAPTURE_FILE" 2>/dev/null | cut -f1)
PACKETS=$(tshark -r "$CAPTURE_FILE" 2>/dev/null | wc -l)

echo ""
echo "[+] Capture complete."
echo "    File     : $CAPTURE_FILE"
echo "    Size     : $FILESIZE"
echo "    Packets  : $PACKETS"
echo ""
echo "[*] Run extract_metrics.sh to pull CSVs from this capture."
