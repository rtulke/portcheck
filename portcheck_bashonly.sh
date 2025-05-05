#!/bin/bash

printf "%-9s %-6s %-6s %-21s %-21s %s\n" "COMMAND" "PID" "USER" "LOCAL ADDRESS" "REMOTE ADDRESS" "STATE"

# TCP state mapping (hex codes to human-readable names)
declare -A states=(
    [01]="ESTABLISHED" [02]="SYN_SENT"   [03]="SYN_RECV" [04]="FIN_WAIT1"
    [05]="FIN_WAIT2"   [06]="TIME_WAIT"  [07]="CLOSE"    [08]="CLOSE_WAIT"
    [09]="LAST_ACK"    [0A]="LISTEN"     [0B]="CLOSING"
)

# Convert hex IP:PORT to human-readable format
parse_addr() {
    local addr=$1
    local ip_hex=${addr%%:*}
    local port_hex=${addr##*:}
    local ip port

    ip=$(printf "%d.%d.%d.%d" \
        "0x${ip_hex:6:2}" "0x${ip_hex:4:2}" "0x${ip_hex:2:2}" "0x${ip_hex:0:2}")
    port=$((16#$port_hex))
    echo "$ip:$port"
}

# Read /proc/net/tcp, skip the header
{
    read -r _  # Skip header line
    while read -r line; do
        set -- $line
        local_hex=$2
        remote_hex=$3
        state_hex=$4
        inode=$10

        local_addr=$(parse_addr "$local_hex")
        remote_addr=$(parse_addr "$remote_hex")
        state=${states[$state_hex]}

        for pid in /proc/[0-9]*; do
            [ -r "$pid/fd" ] || continue
            pidnum=${pid##*/}

            # Read process name
            if read -r comm < "$pid/comm" 2>/dev/null; then
                true
            else
                continue
            fi

            # Read UID from /proc/$pid/status
            uid=""
            while read -r key val _; do
                [ "$key" = "Uid:" ] && uid=$val && break
            done < "$pid/status" 2>/dev/null

            # Resolve username from /etc/passwd
            user=""
            while IFS=: read -r name _ uid_pw _; do
                [ "$uid_pw" = "$uid" ] && user=$name && break
            done < /etc/passwd

            # Check open file descriptors for socket match
            for fd in "$pid/fd/"*; do
                [ -L "$fd" ] || continue
                link=$(readlink "$fd" 2>/dev/null) || continue

                case "$link" in
                    socket:\[*\])
                        fd_inode=${link#*[}
                        fd_inode=${fd_inode%]}
                        if [ "$fd_inode" = "$inode" ]; then
                            printf "%-9s %-6s %-6s %-21s %-21s %s\n" \
                                "$comm" "$pidnum" "$user" "$local_addr" "$remote_addr" "$state"
                            break
                        fi
                        ;;
                esac
            done
        done
    done
} < /proc/net/tcp
