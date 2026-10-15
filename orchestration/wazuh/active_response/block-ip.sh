#!/bin/bash
# ==============================================================================
# SecOps Astrea Platform - Active Response: Block IP (Firewall Drop)
# File: orchestration/wazuh/active_response/block-ip.sh
#
# Description:
#   Extracts attacker IP (srcip) from Wazuh STDIN JSON payload and applies
#   immediate iptables DROP rules on Linux endpoints.
#
# Actions:
#   - add:    Inserts iptables rule dropping incoming traffic from attacker IP:
#             iptables -I INPUT -s <srcip> -j DROP
#   - delete: Removes corresponding iptables DROP rule.
#
# Audit Log:
#   Appends timestamp, IP, action, and status to /var/ossec/logs/active-responses.log.
# ==============================================================================

set -u

LOG_FILE="${WAZUH_AR_LOG_FILE:-/var/ossec/logs/active-responses.log}"

# ------------------------------------------------------------------------------
# Logging Helper
# ------------------------------------------------------------------------------
log_event() {
    local action="$1"
    local ip="$2"
    local status="$3"
    local message="$4"
    local timestamp
    timestamp=$(date '+%Y/%m/%d %H:%M:%S' 2>/dev/null || date)
    local log_entry="${timestamp} block-ip.sh: Action: ${action} - IP: ${ip} - Status: ${status} - ${message}"

    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    if [ -d "$log_dir" ] || mkdir -p "$log_dir" 2>/dev/null; then
        echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true
    fi

    echo "$log_entry"
}

# ------------------------------------------------------------------------------
# IP Validation Helper
# ------------------------------------------------------------------------------
is_valid_ip() {
    local ip="$1"
    if [ -z "$ip" ] || [ "$ip" = "127.0.0.1" ] || [ "$ip" = "0.0.0.0" ] || [ "$ip" = "localhost" ]; then
        return 1
    fi

    # Check for loopback range 127.0.0.0/8
    if echo "$ip" | grep -Eq '^127\.'; then
        return 1
    fi

    # IPv4 regex check
    if echo "$ip" | grep -Eq '^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])$'; then
        return 0
    fi

    # IPv6 regex check
    if echo "$ip" | grep -Eq '^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'; then
        return 0
    fi

    return 1
}

# ------------------------------------------------------------------------------
# Read Input from STDIN (Wazuh Active Response JSON)
# ------------------------------------------------------------------------------
INPUT_JSON=""
if [ ! -t 0 ]; then
    INPUT_JSON=$(cat)
fi

ACTION=""
SRCIP=""

# ------------------------------------------------------------------------------
# Parse Action and Attacker IP from JSON
# ------------------------------------------------------------------------------
if [ -n "$INPUT_JSON" ]; then
    PYTHON_BIN=""
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="python3"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN="python"
    fi

    if [ -n "$PYTHON_BIN" ]; then
        PARSED=$(echo "$INPUT_JSON" | "$PYTHON_BIN" -c '
import sys, json
try:
    data = json.load(sys.stdin)
    cmd = data.get("command", "")
    params = data.get("parameters", {})
    alert = params.get("alert", {})
    srcip = None
    if isinstance(alert, dict):
        data_block = alert.get("data")
        if isinstance(data_block, dict):
            srcip = data_block.get("srcip")
        if not srcip:
            srcip = alert.get("srcip")
    if not srcip and "extra_args" in params:
        args = params.get("extra_args", [])
        if args:
            srcip = args[0]
    if not cmd and "extra_args" in params:
        args = params.get("extra_args", [])
        if args:
            cmd = args[0]
    cmd_str = str(cmd).strip().lower() if cmd else ""
    ip_str = str(srcip).strip() if srcip else ""
    print(cmd_str + "|" + ip_str)
except Exception:
    pass
' 2>/dev/null)
        if [ -n "$PARSED" ]; then
            ACTION=$(echo "$PARSED" | cut -d'|' -f1)
            SRCIP=$(echo "$PARSED" | cut -d'|' -f2)
        fi
    fi

    if [ -z "$ACTION" ] && command -v jq >/dev/null 2>&1; then
        ACTION=$(echo "$INPUT_JSON" | jq -r '.command // empty' 2>/dev/null | tr '[:upper:]' '[:lower:]')
    fi
    if [ -z "$SRCIP" ] && command -v jq >/dev/null 2>&1; then
        SRCIP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.srcip // .parameters.alert.srcip // .parameters.extra_args[0] // empty' 2>/dev/null)
    fi

    if [ -z "$ACTION" ]; then
        ACTION=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | tr '[:upper:]' '[:lower:]')
    fi
    if [ -z "$SRCIP" ]; then
        SRCIP=$(echo "$INPUT_JSON" | sed -n 's/.*"srcip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    fi
fi

# Fallback to positional parameters: block-ip.sh [add|delete] [user] [srcip]
if [ -z "$ACTION" ] && [ $# -ge 1 ]; then
    ACTION=$(echo "$1" | tr '[:upper:]' '[:lower:]')
fi

if [ -z "$SRCIP" ]; then
    if [ $# -ge 3 ] && is_valid_ip "$3"; then
        SRCIP="$3"
    elif [ $# -ge 2 ] && is_valid_ip "$2"; then
        SRCIP="$2"
    fi
fi

# Normalize action
case "$ACTION" in
    add|block)
        ACTION="add"
        ;;
    delete|unblock)
        ACTION="delete"
        ;;
    *)
        log_event "${ACTION:-unknown}" "${SRCIP:-none}" "error" "Invalid or missing action. Expected 'add' or 'delete'. JSON: ${INPUT_JSON:-none}"
        exit 1
        ;;
esac

# Validate IP address
if ! is_valid_ip "$SRCIP"; then
    log_event "$ACTION" "${SRCIP:-empty}" "error" "Invalid, empty, or loopback attacker IP address extracted from input."
    exit 1
fi

# ------------------------------------------------------------------------------
# Pre-flight Check: iptables availability
# ------------------------------------------------------------------------------
if ! command -v iptables >/dev/null 2>&1; then
    log_event "$ACTION" "$SRCIP" "failed" "iptables binary not found on endpoint. IP block cannot proceed."
    exit 1
fi

# ------------------------------------------------------------------------------
# Action: add (Block IP)
# ------------------------------------------------------------------------------
if [ "$ACTION" = "add" ]; then
    if iptables -C INPUT -s "$SRCIP" -j DROP 2>/dev/null; then
        log_event "add" "$SRCIP" "success" "Rule already exists in iptables INPUT chain. IP is already blocked."
        exit 0
    fi

    if iptables -I INPUT 1 -s "$SRCIP" -j DROP; then
        log_event "add" "$SRCIP" "success" "Attacker IP successfully blocked in iptables INPUT chain."
        exit 0
    else
        log_event "add" "$SRCIP" "failed" "Failed to insert DROP rule in iptables INPUT chain."
        exit 1
    fi

# ------------------------------------------------------------------------------
# Action: delete (Unblock IP)
# ------------------------------------------------------------------------------
elif [ "$ACTION" = "delete" ]; then
    REMOVED=0
    while iptables -C INPUT -s "$SRCIP" -j DROP 2>/dev/null; do
        iptables -D INPUT -s "$SRCIP" -j DROP
        REMOVED=1
    done

    if [ "$REMOVED" -eq 1 ]; then
        log_event "delete" "$SRCIP" "success" "Attacker IP successfully unblocked and removed from iptables."
    else
        log_event "delete" "$SRCIP" "success" "Attacker IP was not present in iptables INPUT chain."
    fi
    exit 0
fi
