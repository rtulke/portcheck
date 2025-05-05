#!/bin/bash

printf "%-9s %-9s %-20s %-21s %-21s %s\n" "COMMAND" "PID" "USER" "LOCAL ADDRESS" "REMOTE ADDRESS" "STATE"

# TCP Status Mapping
declare -A states=(
    [01]="ESTABLISHED" [02]="SYN_SENT" [03]="SYN_RECV"
    [04]="FIN_WAIT1" [05]="FIN_WAIT2" [06]="TIME_WAIT"
    [07]="CLOSE" [08]="CLOSE_WAIT" [09]="LAST_ACK"
    [0A]="LISTEN" [0B]="CLOSING"
)

# IP und Port aus hex umwandeln
parse_addr() {
    ip_hex=${1%:*}
    port_hex=${1#*:}
    ip_dec=$(printf "%d.%d.%d.%d" 0x${ip_hex:6:2} 0x${ip_hex:4:2} 0x${ip_hex:2:2} 0x${ip_hex:0:2})
    port_dec=$((16#$port_hex))
    echo "$ip_dec:$port_dec"
}

# Mapping: inode -> "PID CMD USER"
declare -A inode_map

for pid_dir in /proc/[0-9]*; do
    pid=${pid_dir##*/}
    cmd=$(cat "$pid_dir/comm" 2>/dev/null)
    uid=$(awk '/Uid:/ {print $2}' "$pid_dir/status" 2>/dev/null)
    user=$(getent passwd "$uid" | cut -d: -f1)

    [ -z "$cmd" ] && continue

    for fd in "$pid_dir"/fd/*; do
        [ -L "$fd" ] || continue
        link=$(readlink "$fd" 2>/dev/null)
        [[ "$link" =~ socket:\[\d+\] ]] || continue
        inode=$(echo "$link" | grep -oP '\[\K[0-9]+')
        inode_map["$inode"]="$pid $cmd $user"
    done
done

##debugging
echo "Inode map enthält ${#inode_map[@]} Einträge"


# Jetzt /proc/net/tcp durchgehen
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
