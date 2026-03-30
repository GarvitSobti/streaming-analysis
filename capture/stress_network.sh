#!/bin/bash
# =============================================================================
# stress_network.sh — Apply / remove network conditions via tc + netem
# CS204 Computer Networks Project
#
# Usage:
#   ./stress_network.sh <condition> [interface]
#
# Conditions:
#   baseline        — no impairment (just show current state)
#   loss5           — 5% random packet loss
#   delay100        — 100ms added latency (±10ms jitter)
#   combined        — 5% loss + 100ms delay (worst-case scenario)
#   reset           — remove ALL tc rules (restore normal network)
#   status          — show current tc rules without changing anything
# =============================================================================

set -euo pipefail

CONDITION=${1:?"Usage: $0 <condition> [interface]
Conditions: baseline | loss5 | delay100 | combined | reset | status"}
INTERFACE=${2:-$(ip route | awk '/^default/ {print $5; exit}')}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[!] This script requires sudo. Re-running with sudo..."
        exec sudo "$0" "$@"
    fi
}

show_status() {
    echo "--- Current tc rules for $INTERFACE ---"
    tc qdisc show dev "$INTERFACE"
}

case "$CONDITION" in
    baseline)
        echo "[*] Baseline: removing any existing rules on $INTERFACE"
        check_root "$@"
        tc qdisc del dev "$INTERFACE" root 2>/dev/null && \
            echo "[+] Rules cleared — network is now unimpaired." || \
            echo "[+] No existing rules found — already at baseline."
        show_status
        ;;

    loss5)
        check_root "$@"
        echo "[*] Applying 5% random packet loss on $INTERFACE"
        tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
        tc qdisc add dev "$INTERFACE" root netem loss 5%
        echo "[+] Done."
        show_status
        ;;

    delay100)
        check_root "$@"
        echo "[*] Applying 100ms delay (±10ms) on $INTERFACE"
        tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
        tc qdisc add dev "$INTERFACE" root netem delay 100ms 10ms distribution normal
        echo "[+] Done."
        show_status
        ;;

    combined)
        check_root "$@"
        echo "[*] Applying 5% loss + 100ms delay on $INTERFACE (worst-case)"
        tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
        tc qdisc add dev "$INTERFACE" root netem delay 100ms 10ms loss 5%
        echo "[+] Done."
        show_status
        ;;

    reset)
        check_root "$@"
        echo "[*] Resetting all tc rules on $INTERFACE"
        tc qdisc del dev "$INTERFACE" root 2>/dev/null && \
            echo "[+] All rules removed." || \
            echo "[+] No rules to remove."
        show_status
        ;;

    status)
        show_status
        ;;

    *)
        echo "[!] Unknown condition: $CONDITION"
        echo "    Valid: baseline | loss5 | delay100 | combined | reset | status"
        exit 1
        ;;
esac
