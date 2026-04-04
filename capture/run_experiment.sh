#!/bin/bash
# =============================================================================
# run_experiment.sh — Full experiment orchestrator
# CS204 Computer Networks Project
#
# Runs captures for each platform × stream_type × network_condition combo.
# Edit the config section below to match your setup before running.
#
# Usage:
#   ./run_experiment.sh
#
# Workflow per run:
#   1. Print instructions (open this stream type on this platform)
#   2. Wait for user confirmation that stream is live
#   3. Run capture.sh for CAPTURE_DURATION seconds
#   4. Immediately run extract_metrics.sh on the new .pcap
#   5. Move to next combo
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── CONFIG — edit these ────────────────────────────────────────────────────
CAPTURE_DURATION=180        # seconds per capture (3 min)
EXTRACTION_PAUSE=5          # seconds to wait after capture before extraction

# Platforms and their known server IPs (fill in after running identify_servers.sh)
# Format: "platform:server_ip" — leave IP empty to capture all traffic
declare -A PLATFORM_IPS=(
    ["youtube"]=""
    ["twitch"]=""
    ["tiktok"]=""
    ["instagram"]=""
)

# Stream types to test
STREAM_TYPES=("dynamic" "static")

# Network conditions to test (comment out ones you don't want)
NETWORK_CONDITIONS=("baseline")
# NETWORK_CONDITIONS=("baseline" "loss5" "delay100")
# ─── END CONFIG ─────────────────────────────────────────────────────────────

PLATFORMS=("youtube" "twitch" "tiktok" "instagram")
LOG_FILE="${SCRIPT_DIR}/../results/experiment_log_$(date +%Y%m%d_%H%M%S).txt"
mkdir -p "${SCRIPT_DIR}/../results"
declare -A RUNS_PER_COMBO

log() {
    echo "$*" | tee -a "$LOG_FILE"
}

prompt_runs_per_combo() {
    local key
    local runs
    local default_runs=1

    log ""
    log "Set how many runs you want for each platform / stream type combo."
    log "Press ENTER to use default (${default_runs}) for any prompt."

    for PLATFORM in "${PLATFORMS[@]}"; do
        for STREAM_TYPE in "${STREAM_TYPES[@]}"; do
            key="${PLATFORM}|${STREAM_TYPE}"
            while true; do
                read -r -p "Runs for ${PLATFORM} / ${STREAM_TYPE} [${default_runs}]: " runs
                runs="${runs:-$default_runs}"
                if [[ "$runs" =~ ^[0-9]+$ ]]; then
                    RUNS_PER_COMBO["$key"]="$runs"
                    break
                fi
                log "[!] Invalid run count '$runs'. Enter a whole number >= 0."
            done
        done
    done
}

wait_for_user() {
    local msg=$1
    echo ""
    log ">>> ACTION REQUIRED: $msg"
    read -r -p "    Press ENTER when ready (or type 'skip' to skip this run): " input
    if [[ "$input" == "skip" ]]; then
        return 1
    fi
    return 0
}

log "============================================"
log " CS204 Streaming Experiment — $(date)"
log "============================================"
log " Platforms     : ${PLATFORMS[*]}"
log " Stream types  : ${STREAM_TYPES[*]}"
log " Conditions    : ${NETWORK_CONDITIONS[*]}"
log " Duration/run  : ${CAPTURE_DURATION}s"
log "============================================"

prompt_runs_per_combo

TOTAL_PER_CONDITION=0
for PLATFORM in "${PLATFORMS[@]}"; do
    for STREAM_TYPE in "${STREAM_TYPES[@]}"; do
        TOTAL_PER_CONDITION=$(( TOTAL_PER_CONDITION + RUNS_PER_COMBO["${PLATFORM}|${STREAM_TYPE}"] ))
    done
done

TOTAL=$(( TOTAL_PER_CONDITION * ${#NETWORK_CONDITIONS[@]} ))
CURRENT=0

log ""
log " Planned runs per condition: $TOTAL_PER_CONDITION"
log " Planned total runs        : $TOTAL"

for CONDITION in "${NETWORK_CONDITIONS[@]}"; do
    log ""
    log "=== Network Condition: $CONDITION ==="

    # Apply network condition (baseline = normal)
    if [[ "$CONDITION" != "baseline" ]]; then
        log "[*] Applying network condition: $CONDITION"
        bash "${SCRIPT_DIR}/stress_network.sh" "$CONDITION" || {
            log "[!] Failed to apply condition $CONDITION — skipping condition."
            continue
        }
    fi

    for PLATFORM in "${PLATFORMS[@]}"; do
        for STREAM_TYPE in "${STREAM_TYPES[@]}"; do
            RUNS_FOR_COMBO=${RUNS_PER_COMBO["${PLATFORM}|${STREAM_TYPE}"]}
            if [[ "$RUNS_FOR_COMBO" -eq 0 ]]; then
                log "[SKIPPED] $PLATFORM / $STREAM_TYPE / $CONDITION (0 planned runs)"
                continue
            fi

            SERVER_IP="${PLATFORM_IPS[$PLATFORM]:-""}"

            for RUN_INDEX in $(seq 1 "$RUNS_FOR_COMBO"); do
                CURRENT=$(( CURRENT + 1 ))

                log ""
                log "--- Run $CURRENT / $TOTAL ---"
                log " Platform    : $PLATFORM"
                log " Stream type : $STREAM_TYPE  (dynamic=game/action, static=chat/talking)"
                log " Condition   : $CONDITION"
                log " Repeat      : ${RUN_INDEX} / ${RUNS_FOR_COMBO}"
                log " Server IP   : ${SERVER_IP:-"(auto)"}"

                # Describe the stream to open
                if [[ "$STREAM_TYPE" == "dynamic" ]]; then
                    STREAM_DESC="a GAME or action stream (fast movement, high bitrate variation)"
                else
                    STREAM_DESC="a CHAT or talking-head stream (mostly static, low bitrate variation)"
                fi

                if ! wait_for_user "Open ${PLATFORM} Live — find $STREAM_DESC — let it buffer fully, then press ENTER"; then
                    log "[SKIPPED] $PLATFORM / $STREAM_TYPE / $CONDITION (repeat ${RUN_INDEX}/${RUNS_FOR_COMBO})"
                    continue
                fi

                log "[*] Starting capture at $(date)"
                bash "${SCRIPT_DIR}/capture.sh" \
                    "$PLATFORM" \
                    "$SERVER_IP" \
                    "$CAPTURE_DURATION" \
                    "$STREAM_TYPE" \
                    2>&1 | tee -a "$LOG_FILE"

                # Find the most recently created pcap for this platform
                LATEST_PCAP=$(ls -t "${SCRIPT_DIR}/../data/${PLATFORM}_${STREAM_TYPE}_"*.pcap 2>/dev/null | head -1)

                if [[ -f "$LATEST_PCAP" ]]; then
                    log "[*] Extracting metrics from $LATEST_PCAP..."
                    sleep "$EXTRACTION_PAUSE"
                    bash "${SCRIPT_DIR}/../analysis/extract_metrics.sh" \
                        "$LATEST_PCAP" \
                        2>&1 | tee -a "$LOG_FILE"
                    log "[+] Extraction done."
                else
                    log "[!] No pcap found for $PLATFORM / $STREAM_TYPE — skipping extraction."
                fi

                log "[+] Run $CURRENT complete."
            done
        done
    done

    # Always reset network after each condition block
    if [[ "$CONDITION" != "baseline" ]]; then
        log "[*] Resetting network conditions..."
        bash "${SCRIPT_DIR}/stress_network.sh" reset 2>/dev/null || true
    fi
done

log ""
log "============================================"
log " All runs complete. $(date)"
log " Log saved to: $LOG_FILE"
log ""
log " Next step: run the Python analyser:"
log "   cd ../analysis && python analyze.py"
log "============================================"
