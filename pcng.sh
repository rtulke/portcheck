#!/bin/bash

# table headline
printf "%-9s %-9s %-20s %-21s %-21s %s\n" "COMMAND" "PID" "USER" "LOCAL ADDRESS" "REMOTE ADDRESS" "STATE"

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

# Mapping: Inode → "PID CMD USER"
declare -A inode_map

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
tail -n +2 /proc/net/tcp | while read -r line; do
    fields=($line)
    local_addr_parsed=$(parse_addr "${fields[1]}")
    rem_addr_parsed=$(parse_addr "${fields[2]}")
    state_code="${fields[3]}"
    inode="${fields[9]}"
    state=${states[$state_code]}

    if [[ -n "${inode_map[$inode]}" ]]; then
        read -r pid cmd user <<< "${inode_map[$inode]}"
        printf "%-9s %-9s %-20s %-21s %-21s %s\n" "$cmd" "$pid" "$user" "$local_addr_parsed" "$rem_addr_parsed" "$state"
    fi
done
