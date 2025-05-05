#!/bin/bash

# Ausgabe-Header wie bei lsof
printf "%-9s %-8s %-6s %-21s %-21s %s\n" "COMMAND" "PID" "USER" "LOCAL ADDRESS" "REMOTE ADDRESS" "STATE"

# TCP Status Mapping
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

# IP und Port aus hex in lesbares Format
parse_addr() {
    ip_hex=$(echo "$1" | cut -d':' -f1)
    port_hex=$(echo "$1" | cut -d':' -f2)
    ip_dec=$(printf "%d.%d.%d.%d" 0x${ip_hex:6:2} 0x${ip_hex:4:2} 0x${ip_hex:2:2} 0x${ip_hex:0:2})
    port_dec=$((16#$port_hex))
    echo "$ip_dec:$port_dec"
}

# Alle Zeilen von /proc/net/tcp (außer Header) durchgehen
tail -n +2 /proc/net/tcp | while read -r line; do
    local_addr=$(echo "$line" | awk '{print $2}')
    rem_addr=$(echo "$line" | awk '{print $3}')
    inode=$(echo "$line" | awk '{print $10}')
    state_code=$(echo "$line" | awk '{print $4}')
    state=${states[$state_code]}

    local_addr_parsed=$(parse_addr "$local_addr")
    rem_addr_parsed=$(parse_addr "$rem_addr")

    # Durch alle PIDs schauen
    for pid in $(ls -d /proc/[0-9]* 2>/dev/null); do
        cmdline=$(cat "$pid/comm" 2>/dev/null)
        uid=$(awk '/Uid:/ {print $2}' "$pid/status" 2>/dev/null)
        user=$(getent passwd "$uid" | cut -d: -f1)

        # Alle FDs nach dem Inode durchsuchen
        for fd in "$pid"/fd/*; do
            [ -L "$fd" ] || continue
            link=$(readlink "$fd" 2>/dev/null)
            if [[ "$link" == socket:* ]]; then
                fd_inode=$(echo "$link" | grep -oP '\[\K[0-9]+')
                if [[ "$fd_inode" == "$inode" ]]; then
                    printf "%-9s %-6s %-6s %-21s %-21s %s\n" "$cmdline" "${pid##*/}" "$user" "$local_addr_parsed" "$rem_addr_parsed" "$state"
                    break
                fi
            fi
        done
    done
done
