#!/bin/bash
# =============================================================================
# identify_servers.sh — Find CDN server IPs while a stream is playing
# CS204 Computer Networks Project
#
# Run this WHILE your stream is already playing in the browser.
# It sniffs for large packets (video segments) and ranks remote IPs by volume.
#
# Usage:
#   ./identify_servers.sh [sample_duration_seconds]
#   ./identify_servers.sh 30
# =============================================================================

set -euo pipefail

SAMPLE_DURATION=${1:-30}
MIN_FRAME_SIZE=1200   # bytes — video frames are large; control signals are small
INTERFACE=$(ip route | awk '/^default/ {print $5; exit}')
TMP_PCAP="/tmp/id_servers_$$.pcap"

echo "============================================"
echo " Server Identification"
echo "============================================"
echo " Interface : $INTERFACE"
echo " Sample    : ${SAMPLE_DURATION}s"
echo " Min frame : ${MIN_FRAME_SIZE} bytes (filters out control packets)"
echo "============================================"
echo ""
echo "[*] Sniffing for ${SAMPLE_DURATION}s — make sure the stream is playing..."

# Capture a short sample
tshark -i "$INTERFACE" \
       -a duration:"$SAMPLE_DURATION" \
       -w "$TMP_PCAP" \
       -q 2>/dev/null

echo ""
echo "--- Top remote IPs by data volume (likely CDN nodes) ---"
tshark -r "$TMP_PCAP" \
       -T fields \
       -e ip.dst \
       -e frame.len \
       -Y "frame.len > ${MIN_FRAME_SIZE} and tcp" \
       2>/dev/null | \
    awk '{bytes[$1]+=$2; count[$1]++}
         END {for (ip in bytes) printf "%10d bytes  %5d pkts  %s\n", bytes[ip], count[ip], ip}' | \
    sort -rn | \
    head -15

echo ""
echo "--- All established TCP connections right now ---"
ss -tnp state established | \
    awk 'NR>1 {print $4, $5, $6}' | \
    column -t

echo ""
echo "--- Reverse DNS for top IPs (shows CDN provider) ---"
tshark -r "$TMP_PCAP" \
       -T fields \
       -e ip.dst \
       -e frame.len \
       -Y "frame.len > ${MIN_FRAME_SIZE} and tcp" \
       2>/dev/null | \
    awk '{bytes[$1]+=$2} END {for (ip in bytes) print bytes[ip], ip}' | \
    sort -rn | head -5 | \
    while read -r _bytes ip; do
        hostname=$(host "$ip" 2>/dev/null | awk '/domain name/ {print $NF}' | head -1 || echo "N/A")
        printf "  %-18s  ->  %s\n" "$ip" "$hostname"
    done

rm -f "$TMP_PCAP"

echo ""
echo "[*] Pick the IP with the highest byte count — that is your video CDN server."
echo "[*] Pass it to capture.sh as the second argument."
