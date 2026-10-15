#!/bin/bash
# ==============================================================================
# SecOps Astrea Platform - Active Response: Isolate Host
# File: orchestration/wazuh/active_response/isolate-host.sh
#
# Description:
#   Performs active network containment on Linux endpoints using iptables.
#   Preserves Wazuh Manager communication (ports 1514/TCP, 1514/UDP, 1515/TCP)
#   and loopback interface (lo) to maintain management and telemetry access.
#
# Actions:
#   - add:    Isolates the host by blocking all inbound and outbound traffic
#             except Wazuh Manager ports and loopback.
#   - delete: Tears down isolation rules, restoring normal network connectivity.
#
# Audit Log:
#   Writes structured logs to /var/ossec/logs/active-responses.log.
# ==============================================================================

set -u

LOG_FILE="${WAZUH_AR_LOG_FILE:-/var/ossec/logs/active-responses.log}"
CHAIN_NAME="WAZUH_ISOLATION"

# ------------------------------------------------------------------------------
# Logging Helper
# ------------------------------------------------------------------------------
log_event() {
    local action="$1"
    local status="$2"
    local message="$3"
    local timestamp
    timestamp=$(date '+%Y/%m/%d %H:%M:%S' 2>/dev/null || date)
    local log_entry="${timestamp} isolate-host.sh: Action: ${action} - Status: ${status} - ${message}"

    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    if [ -d "$log_dir" ] || mkdir -p "$log_dir" 2>/dev/null; then
        echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true
    fi

    echo "$log_entry"
}

# ------------------------------------------------------------------------------
# Read Input from STDIN (Wazuh Active Response JSON)
# ------------------------------------------------------------------------------
INPUT_JSON=""
if [ ! -t 0 ]; then
    INPUT_JSON=$(cat)
fi

# ------------------------------------------------------------------------------
# Parse Action from JSON or Positional Arguments
# ------------------------------------------------------------------------------
ACTION=""
if [ -n "$INPUT_JSON" ]; then
    PYTHON_BIN=""
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="python3"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN="python"
    fi

    if [ -n "$PYTHON_BIN" ]; then
        ACTION=$(echo "$INPUT_JSON" | "$PYTHON_BIN" -c '
import sys, json
try:
    data = json.load(sys.stdin)
    cmd = data.get("command") or ""
    if not cmd and "parameters" in data:
        args = data.get("parameters", {}).get("extra_args", [])
        if args:
            cmd = args[0]
    cmd_str = str(cmd).strip().lower() if cmd else ""
    print(cmd_str)
except Exception:
    pass
' 2>/dev/null)
    fi

    if [ -z "$ACTION" ] && command -v jq >/dev/null 2>&1; then
        ACTION=$(echo "$INPUT_JSON" | jq -r '.command // .parameters.extra_args[0] // empty' 2>/dev/null | tr '[:upper:]' '[:lower:]')
    fi

    if [ -z "$ACTION" ]; then
        ACTION=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | tr '[:upper:]' '[:lower:]')
    fi
fi

# Fallback to positional argument if provided
if [ -z "$ACTION" ] && [ $# -ge 1 ]; then
    ACTION=$(echo "$1" | tr '[:upper:]' '[:lower:]')
fi

# Normalize actions: "isolate" -> "add", "unisolate" -> "delete"
case "$ACTION" in
    add|isolate)
        ACTION="add"
        ;;
    delete|unisolate)
        ACTION="delete"
        ;;
    *)
        log_event "${ACTION:-none}" "error" "Invalid or missing action. Expected 'add' or 'delete'. JSON: ${INPUT_JSON:-none}"
        exit 1
        ;;
esac

# ------------------------------------------------------------------------------
# Pre-flight Check: iptables availability
# ------------------------------------------------------------------------------
if ! command -v iptables >/dev/null 2>&1; then
    log_event "$ACTION" "failed" "iptables binary not found on endpoint. Isolation cannot proceed."
    exit 1
fi

# ------------------------------------------------------------------------------
# Action: add (Isolate Host)
# ------------------------------------------------------------------------------
if [ "$ACTION" = "add" ]; then
    # Create isolation chain if it does not exist
    iptables -N "$CHAIN_NAME" 2>/dev/null || true

    # Flush any previous rules in the isolation chain
    iptables -F "$CHAIN_NAME" 2>/dev/null || true

    # Rule 1: Allow all loopback interface traffic (inbound and outbound)
    iptables -A "$CHAIN_NAME" -i lo -j ACCEPT
    iptables -A "$CHAIN_NAME" -o lo -j ACCEPT

    # Rule 2: Preserve Wazuh Manager agent communication on port 1514 (TCP & UDP)
    iptables -A "$CHAIN_NAME" -p tcp --dport 1514 -j ACCEPT
    iptables -A "$CHAIN_NAME" -p tcp --sport 1514 -j ACCEPT
    iptables -A "$CHAIN_NAME" -p udp --dport 1514 -j ACCEPT
    iptables -A "$CHAIN_NAME" -p udp --sport 1514 -j ACCEPT

    # Rule 3: Preserve Wazuh registration/auth port 1515 (TCP & UDP)
    iptables -A "$CHAIN_NAME" -p tcp --dport 1515 -j ACCEPT
    iptables -A "$CHAIN_NAME" -p tcp --sport 1515 -j ACCEPT
    iptables -A "$CHAIN_NAME" -p udp --dport 1515 -j ACCEPT
    iptables -A "$CHAIN_NAME" -p udp --sport 1515 -j ACCEPT

    # Rule 4: Preserve established and related connections for management stability
    iptables -A "$CHAIN_NAME" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A "$CHAIN_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # Rule 5: Drop all other incoming and outgoing traffic
    iptables -A "$CHAIN_NAME" -j DROP

    # Attach chain to INPUT and OUTPUT if not already linked
    if ! iptables -C INPUT -j "$CHAIN_NAME" 2>/dev/null; then
        iptables -I INPUT 1 -j "$CHAIN_NAME"
    fi

    if ! iptables -C OUTPUT -j "$CHAIN_NAME" 2>/dev/null; then
        iptables -I OUTPUT 1 -j "$CHAIN_NAME"
    fi

    log_event "add" "success" "Host network isolated successfully. Preserved loopback and Wazuh Manager port 1514 (TCP/UDP)."
    exit 0

# ------------------------------------------------------------------------------
# Action: delete (Unisolate Host / Restore Connectivity)
# ------------------------------------------------------------------------------
elif [ "$ACTION" = "delete" ]; then
    # Unlink chain from INPUT
    while iptables -D INPUT -j "$CHAIN_NAME" 2>/dev/null; do
        :
    done

    # Unlink chain from OUTPUT
    while iptables -D OUTPUT -j "$CHAIN_NAME" 2>/dev/null; do
        :
    done

    # Flush and delete chain
    iptables -F "$CHAIN_NAME" 2>/dev/null || true
    iptables -X "$CHAIN_NAME" 2>/dev/null || true

    log_event "delete" "success" "Host network isolation removed successfully. Normal network connectivity restored."
    exit 0
fi
