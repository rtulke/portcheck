#!/bin/bash

# Default parameters
FORMAT="table"
IPV6_FORMAT="compressed"

# Help function
show_help() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Display active TCP and TCP6 network connections with process information.

Options:
  --format=FORMAT           Output format: table, csv, json (default: table)
  --ipv6-format=FORMAT      IPv6 address format: compressed, full (default: compressed)
  -h, --help                Show this help message

Examples:
  $(basename "$0")                           # Default table output
  $(basename "$0") --format=csv              # CSV output
  $(basename "$0") --format=json             # JSON output
  $(basename "$0") --ipv6-format=full        # Full IPv6 addresses

EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --format=*)
            FORMAT="${1#*=}"
            if [[ ! "$FORMAT" =~ ^(table|csv|json)$ ]]; then
                echo "Error: Invalid format '$FORMAT'. Use: table, csv, or json" >&2
                exit 1
            fi
            ;;
        --ipv6-format=*)
            IPV6_FORMAT="${1#*=}"
            if [[ ! "$IPV6_FORMAT" =~ ^(compressed|full)$ ]]; then
                echo "Error: Invalid ipv6-format '$IPV6_FORMAT'. Use: compressed or full" >&2
                exit 1
            fi
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Error: Unknown option '$1'" >&2
            echo "Use --help for usage information" >&2
            exit 1
            ;;
    esac
    shift
done

# Error handling and validation
if [[ ! -r /proc/net/tcp ]]; then
    echo "Error: Cannot read /proc/net/tcp. This script requires a Linux system with /proc filesystem." >&2
    exit 1
fi

# Check for IPv6 support (non-fatal)
HAS_IPV6=true
if [[ ! -r /proc/net/tcp6 ]]; then
    echo "Warning: /proc/net/tcp6 not found. IPv6 connections will not be displayed." >&2
    HAS_IPV6=false
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Note: Not running as root. Only connections from your own processes will be visible." >&2
fi

# TCP-Status-Codes
declare -A states=(
    [01]="ESTABLISHED"
    [02]="SYN_SENT"
    [03]="SYN_RECV"
    [04]="FIN_WAIT1"
    [05]="FIN_WAIT2"
    [06]="TIME_WAIT"
    [07]="CLOSE"
    [08]="CLOSE_WAIT"
    [09]="LAST_ACK"
    [0A]="LISTEN"
    [0B]="CLOSING"
)

# Convert IP:Port from hex to readable format
parse_addr() {
    ip_hex=${1%:*}
    port_hex=${1#*:}
    ip_dec=$(printf "%d.%d.%d.%d" 0x${ip_hex:6:2} 0x${ip_hex:4:2} 0x${ip_hex:2:2} 0x${ip_hex:0:2})
    port_dec=$((16#$port_hex))
    echo "$ip_dec:$port_dec"
}

# Compress IPv6 address (RFC 5952 compliant)
compress_ipv6() {
    local addr="$1"

    # Find the longest sequence of consecutive zeros
    local best_start=-1
    local best_len=0
    local curr_start=-1
    local curr_len=0

    IFS=':' read -ra groups <<< "$addr"

    for i in "${!groups[@]}"; do
        if [[ "${groups[$i]}" == "0" ]]; then
            if [[ $curr_start -eq -1 ]]; then
                curr_start=$i
                curr_len=1
            else
                ((curr_len++))
            fi
        else
            if [[ $curr_len -gt $best_len ]]; then
                best_start=$curr_start
                best_len=$curr_len
            fi
            curr_start=-1
            curr_len=0
        fi
    done

    # Check last sequence
    if [[ $curr_len -gt $best_len ]]; then
        best_start=$curr_start
        best_len=$curr_len
    fi

    # Build compressed address
    if [[ $best_len -gt 1 ]]; then
        local result=""
        for i in "${!groups[@]}"; do
            if [[ $i -eq $best_start ]]; then
                if [[ $i -eq 0 ]]; then
                    result="::"
                else
                    result="${result}:"
                fi
            elif [[ $i -ge $best_start && $i -lt $((best_start + best_len)) ]]; then
                continue
            else
                if [[ -n "$result" && "$result" != "::" ]]; then
                    result="${result}:${groups[$i]}"
                else
                    result="${result}${groups[$i]}"
                fi
            fi
        done
        echo "$result"
    else
        echo "$addr"
    fi
}

parse_addr6() {
    ip_hex=${1%:*}
    port_hex=${1#*:}

    # Reorder bytes per 32-bit word
    ip=$(printf "%s:%s:%s:%s:%s:%s:%s:%s" \
        "${ip_hex:6:2}${ip_hex:4:2}" \
        "${ip_hex:2:2}${ip_hex:0:2}" \
        "${ip_hex:14:2}${ip_hex:12:2}" \
        "${ip_hex:10:2}${ip_hex:8:2}" \
        "${ip_hex:22:2}${ip_hex:20:2}" \
        "${ip_hex:18:2}${ip_hex:16:2}" \
        "${ip_hex:30:2}${ip_hex:28:2}" \
        "${ip_hex:26:2}${ip_hex:24:2}"
    )

    port=$((16#$port_hex))

    # Convert to decimal per group and remove leading zeros
    local formatted
    formatted=$(printf "%x:%x:%x:%x:%x:%x:%x:%x" 0x${ip//:/ 0x})

    # Apply format based on user preference
    if [[ "$IPV6_FORMAT" == "full" ]]; then
        # Full format with all groups
        printf "[%s]:%d" "$formatted" "$port"
    else
        # Compressed format (default)
        printf "[%s]:%d" "$(compress_ipv6 "$formatted")" "$port"
    fi
}

# Mapping: Inode → "PID CMD USER"
declare -A inode_map

# Array to store connection data
declare -a connections=()

# Go through all processes
for pid_dir in /proc/[0-9]*; do
    pid=${pid_dir##*/}

    # command and user
    cmd=$(cat "$pid_dir/comm" 2>/dev/null) || continue
    uid=$(awk '/Uid:/ {print $2}' "$pid_dir/status" 2>/dev/null) || continue
    user=$(getent passwd "$uid" | cut -d: -f1)

    [ -z "$cmd" ] && continue

    # Go through all file descriptors of the process.
    for fd in "$pid_dir"/fd/*; do
        [ -L "$fd" ] || continue
        link=$(readlink "$fd" 2>/dev/null) || continue

        echo "$link" | grep -qE '^socket:\[[0-9]+\]$' || continue
        inode=$(echo "$link" | sed -n 's/^socket:\[\([0-9]\+\)\]$/\1/p')
        [ -n "$inode" ] || continue

        inode_map["$inode"]="$pid $cmd $user"
    done
done

# Debug:
# echo "Inodes found: ${#inode_map[@]}"

# Go through TCP connections
while read -r line; do
    fields=($line)
    local_addr_parsed=$(parse_addr "${fields[1]}")
    rem_addr_parsed=$(parse_addr "${fields[2]}")
    state_code="${fields[3]}"
    inode="${fields[9]}"
    state=${states[$state_code]}

    if [[ -n "${inode_map[$inode]}" ]]; then
        read -r pid cmd user <<< "${inode_map[$inode]}"
        connections+=("$cmd|$pid|$user|$local_addr_parsed|$rem_addr_parsed|$state")
    fi
done < <(tail -n +2 /proc/net/tcp)

# Go through TCP6 connections (IPv6)
if [[ "$HAS_IPV6" == "true" ]]; then
    while read -r line; do
        fields=($line)
        local_addr_parsed=$(parse_addr6 "${fields[1]}")
        rem_addr_parsed=$(parse_addr6 "${fields[2]}")
        state_code="${fields[3]}"
        inode="${fields[9]}"
        state=${states[$state_code]}

        if [[ -n "${inode_map[$inode]}" ]]; then
            read -r pid cmd user <<< "${inode_map[$inode]}"
            connections+=("$cmd|$pid|$user|$local_addr_parsed|$rem_addr_parsed|$state")
        fi
    done < <(tail -n +2 /proc/net/tcp6)
fi

# Calculate dynamic column widths
calculate_widths() {
    local -n widths=$1

    # Initialize with header lengths
    widths[0]=7  # COMMAND
    widths[1]=3  # PID
    widths[2]=4  # USER
    widths[3]=13 # LOCAL ADDRESS
    widths[4]=14 # REMOTE ADDRESS
    widths[5]=5  # STATE

    # Calculate max width for each column
    for conn in "${connections[@]}"; do
        IFS='|' read -r cmd pid user local_addr remote_addr state <<< "$conn"

        [[ ${#cmd} -gt ${widths[0]} ]] && widths[0]=${#cmd}
        [[ ${#pid} -gt ${widths[1]} ]] && widths[1]=${#pid}
        [[ ${#user} -gt ${widths[2]} ]] && widths[2]=${#user}
        [[ ${#local_addr} -gt ${widths[3]} ]] && widths[3]=${#local_addr}
        [[ ${#remote_addr} -gt ${widths[4]} ]] && widths[4]=${#remote_addr}
        [[ ${#state} -gt ${widths[5]} ]] && widths[5]=${#state}
    done
}

# Output in table format
output_table() {
    local -a widths
    calculate_widths widths

    # Print header
    printf "%-${widths[0]}s %-${widths[1]}s %-${widths[2]}s %-${widths[3]}s %-${widths[4]}s %s\n" \
        "COMMAND" "PID" "USER" "LOCAL ADDRESS" "REMOTE ADDRESS" "STATE"

    # Print connections
    for conn in "${connections[@]}"; do
        IFS='|' read -r cmd pid user local_addr remote_addr state <<< "$conn"
        printf "%-${widths[0]}s %-${widths[1]}s %-${widths[2]}s %-${widths[3]}s %-${widths[4]}s %s\n" \
            "$cmd" "$pid" "$user" "$local_addr" "$remote_addr" "$state"
    done
}

# Output in CSV format
output_csv() {
    # Print header
    echo "COMMAND,PID,USER,LOCAL ADDRESS,REMOTE ADDRESS,STATE"

    # Print connections
    for conn in "${connections[@]}"; do
        IFS='|' read -r cmd pid user local_addr remote_addr state <<< "$conn"
        # Escape quotes and wrap in quotes if contains comma or quote
        printf '"%s","%s","%s","%s","%s","%s"\n' \
            "${cmd//\"/\"\"}" "${pid//\"/\"\"}" "${user//\"/\"\"}" \
            "${local_addr//\"/\"\"}" "${remote_addr//\"/\"\"}" "${state//\"/\"\"}"
    done
}

# Output in JSON format
output_json() {
    echo "["
    local first=true

    for conn in "${connections[@]}"; do
        IFS='|' read -r cmd pid user local_addr remote_addr state <<< "$conn"

        # Add comma before all but first entry
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi

        # Escape JSON special characters
        cmd=$(printf '%s' "$cmd" | sed 's/\\/\\\\/g; s/"/\\"/g')
        user=$(printf '%s' "$user" | sed 's/\\/\\\\/g; s/"/\\"/g')
        local_addr=$(printf '%s' "$local_addr" | sed 's/\\/\\\\/g; s/"/\\"/g')
        remote_addr=$(printf '%s' "$remote_addr" | sed 's/\\/\\\\/g; s/"/\\"/g')
        state=$(printf '%s' "$state" | sed 's/\\/\\\\/g; s/"/\\"/g')

        printf '  {\n    "command": "%s",\n    "pid": %s,\n    "user": "%s",\n    "local_address": "%s",\n    "remote_address": "%s",\n    "state": "%s"\n  }' \
            "$cmd" "$pid" "$user" "$local_addr" "$remote_addr" "$state"
    done

    echo ""
    echo "]"
}

# Call appropriate output function based on format
case "$FORMAT" in
    csv)
        output_csv
        ;;
    json)
        output_json
        ;;
    table|*)
        output_table
        ;;
esac
