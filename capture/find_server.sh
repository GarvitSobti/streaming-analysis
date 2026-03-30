#!/bin/bash
# find_server.sh
# Identifies the CDN IP address serving the most video traffic.
# Run this WHILE the stream is playing in your browser.
#
# Usage: bash capture/find_server.sh

echo "=== Top active TCP connections (by remote IP) ==="
echo "Open your browser and START the stream, then read the output below."
echo ""

# Show established connections with process name, sorted by remote port
ss -tnp state established | awk 'NR>1 {print $4, $5}' | sort | uniq -c | sort -rn | head -20

echo ""
echo "=== Hint: look for the IP with the most connections or the one from a browser process ==="
echo "Then run: ping -c 20 <that_IP>"
