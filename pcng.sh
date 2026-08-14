#!/bin/bash
#
# pcng - Port Check Next Generation ;D
#
# Lists active TCP/UDP connections together with the owning process, read
# exclusively from /proc. Requires Bash 4.0+ (associative arrays).
#
# Performance note: everything below avoids subshells and external commands
# in the per-connection and per-file-descriptor hot paths. The only processes
# forked at runtime are one `readlink` per PID and one `getent` per distinct
# UID. Helper functions therefore return their result in $REPLY instead of
# writing to stdout, which would require a command substitution (= a fork).

shopt -s nullglob

# Default parameters
FORMAT="table"
IPV6_FORMAT="compressed"
PROTO="tcp"

# Filter state, all disabled by default
LISTEN_ONLY=false
FILTER_STATE=false
FILTER_PORT=false
FILTER_USER=false
FILTER_PID=false

declare -A want_state=()    # hex state code -> 1
declare -A want_port=()     # 4-digit hex port -> 1
declare -A want_uid=()      # numeric uid -> 1
declare -A want_pid=()      # pid -> 1

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
    [0C]="NEW_SYN_RECV"
)

# Reverse map for --state=NAME, built once
declare -A state_codes=()
for _code in "${!states[@]}"; do
    state_codes[${states[$_code]}]=$_code
done
unset _code

# Help function
show_help() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Display active TCP and UDP network connections with process information.

Output options:
  --format=FORMAT           Output format: table, csv, json (default: table)
  --ipv6-format=FORMAT      IPv6 address format: compressed, full (default: compressed)

Selection options:
  --proto=PROTO             Protocol: tcp, udp, all (default: tcp)
  -l, --listen              Only listening sockets (TCP: LISTEN, UDP: unconnected)
  --state=LIST              Only these TCP states, comma separated (e.g. LISTEN,ESTABLISHED)
  --port=LIST               Only these ports, comma separated; matches local or remote
  --user=LIST               Only sockets owned by these users, comma separated (name or uid)
  --pid=LIST                Only sockets of these PIDs, comma separated

  -h, --help                Show this help message

With --proto=all an additional PROTO column is emitted; the default output
format is unchanged.

Examples:
  $(basename "$0")                           # Default table output
  $(basename "$0") --format=csv              # CSV output
  $(basename "$0") --format=json             # JSON output
  $(basename "$0") --ipv6-format=full        # Full IPv6 addresses
  $(basename "$0") -l                        # Listening TCP sockets only
  $(basename "$0") --proto=all -l            # Listening TCP and UDP sockets
  $(basename "$0") --port=80,443             # HTTP/HTTPS connections
  $(basename "$0") --user=root --state=ESTABLISHED

EOF
    exit 0
}

# Split a comma separated option value into the global array $OPT_ITEMS
split_list() {
    IFS=',' read -ra OPT_ITEMS <<< "$1"
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
        --proto=*)
            PROTO="${1#*=}"
            if [[ ! "$PROTO" =~ ^(tcp|udp|all)$ ]]; then
                echo "Error: Invalid proto '$PROTO'. Use: tcp, udp, or all" >&2
                exit 1
            fi
            ;;
        -l|--listen)
            LISTEN_ONLY=true
            FILTER_STATE=true
            want_state[0A]=1
            ;;
        --state=*)
            split_list "${1#*=}"
            for item in "${OPT_ITEMS[@]}"; do
                item=${item^^}
                if [[ -z "${state_codes[$item]}" ]]; then
                    echo "Error: Unknown state '$item'. Valid: ${states[*]}" >&2
                    exit 1
                fi
                want_state[${state_codes[$item]}]=1
            done
            FILTER_STATE=true
            ;;
        --port=*)
            split_list "${1#*=}"
            for item in "${OPT_ITEMS[@]}"; do
                if [[ ! "$item" =~ ^[0-9]+$ ]] || [[ $item -gt 65535 ]]; then
                    echo "Error: Invalid port '$item'. Use 0-65535" >&2
                    exit 1
                fi
                # /proc stores ports as upper-case 4-digit hex
                printf -v port_hex "%04X" "$item"
                want_port[$port_hex]=1
            done
            FILTER_PORT=true
            ;;
        --user=*)
            split_list "${1#*=}"
            for item in "${OPT_ITEMS[@]}"; do
                if [[ "$item" =~ ^[0-9]+$ ]]; then
                    want_uid[$item]=1
                else
                    entry=$(getent passwd "$item")
                    if [[ -z "$entry" ]]; then
                        echo "Error: Unknown user '$item'" >&2
                        exit 1
                    fi
                    IFS=':' read -r _ _ uid _ <<< "$entry"
                    want_uid[$uid]=1
                fi
            done
            FILTER_USER=true
            ;;
        --pid=*)
            split_list "${1#*=}"
            for item in "${OPT_ITEMS[@]}"; do
                if [[ ! "$item" =~ ^[0-9]+$ ]]; then
                    echo "Error: Invalid pid '$item'" >&2
                    exit 1
                fi
                want_pid[$item]=1
            done
            FILTER_PID=true
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

# The PROTO column would change the output format for existing consumers, so
# it appears only when more than one protocol was explicitly requested.
SHOW_PROTO=false
[[ "$PROTO" == "all" ]] && SHOW_PROTO=true

# Tables to read: "file proto is_ipv6"
declare -a TABLES=()
if [[ "$PROTO" == "tcp" || "$PROTO" == "all" ]]; then
    TABLES+=("/proc/net/tcp tcp 0" "/proc/net/tcp6 tcp6 1")
fi
if [[ "$PROTO" == "udp" || "$PROTO" == "all" ]]; then
    TABLES+=("/proc/net/udp udp 0" "/proc/net/udp6 udp6 1")
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Note: Not running as root. Only connections from your own processes will be visible." >&2
fi

# Address decoding
#
# /proc/net/* stores addresses as little-endian hex, so the byte order has to
# be reversed on read: IPv4 across the whole word, IPv6 within each of the
# four 32-bit words.

# Convert IP:Port from hex to readable format -> $REPLY
parse_addr() {
    local hex=${1%:*} port=${1#*:}
    printf -v REPLY "%d.%d.%d.%d:%d" \
        "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}" "0x$port"
}

# Compress IPv6 address (RFC 5952 compliant) -> $REPLY
compress_ipv6() {
    local -a groups
    local i best_start=-1 best_len=0 curr_start=-1 curr_len=0 result=""

    IFS=':' read -ra groups <<< "$1"

    # Find the longest sequence of consecutive zeros (first one wins on a tie)
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

    # A single zero group is never compressed (RFC 5952 4.2.2)
    if [[ $best_len -le 1 ]]; then
        REPLY=$1
        return
    fi

    # Build compressed address
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

    # A run reaching the end leaves a single trailing colon ("2001:db8:"), so
    # close it into the required "::" form. A run starting at index 0 already
    # emitted both colons and must not get a third one.
    if [[ $best_start -gt 0 && $((best_start + best_len)) -eq ${#groups[@]} ]]; then
        result="${result}:"
    fi

    REPLY=$result
}

# Convert IPv6 address:Port from hex to readable format -> $REPLY
parse_addr6() {
    local hex=${1%:*} port=${1#*:} ip

    # Reorder bytes per 32-bit word and strip leading zeros per group
    printf -v ip "%x:%x:%x:%x:%x:%x:%x:%x" \
        "0x${hex:6:2}${hex:4:2}"   "0x${hex:2:2}${hex:0:2}" \
        "0x${hex:14:2}${hex:12:2}" "0x${hex:10:2}${hex:8:2}" \
        "0x${hex:22:2}${hex:20:2}" "0x${hex:18:2}${hex:16:2}" \
        "0x${hex:30:2}${hex:28:2}" "0x${hex:26:2}${hex:24:2}"

    if [[ "$IPV6_FORMAT" != "full" ]]; then
        # IPv4-mapped addresses use the mixed notation (RFC 5952 section 5).
        # The last 32-bit word holds the embedded IPv4 address.
        if [[ "$ip" == 0:0:0:0:0:ffff:* ]]; then
            printf -v REPLY "[::ffff:%d.%d.%d.%d]:%d" \
                "0x${hex:30:2}" "0x${hex:28:2}" "0x${hex:26:2}" "0x${hex:24:2}" \
                "0x$port"
            return
        fi
        compress_ipv6 "$ip"
        ip=$REPLY
    fi

    printf -v REPLY "[%s]:%d" "$ip" "0x$port"
}

# Phase 1: read the connection tables
#
# This runs before the process scan so that the (expensive) inode -> process
# mapping can be restricted to inodes that actually appear in a connection.
# State, port and user filters are applied here, on the raw hex fields, so
# that filtered-out sockets never reach the process scan at all.

declare -A want=()          # inode -> 1, the inodes worth looking up
declare -a rec_proto rec_v6 rec_local rec_rem rec_state rec_uid rec_inode

read_conn_table() {
    local file=$1 proto=$2 v6=$3
    local lhex rhex st uid ino

    {
        read -r _                                           # header line
        while read -r _ lhex rhex st _ _ _ uid _ ino _; do
            # inode 0 means the socket has no owning process (e.g. TIME_WAIT)
            [[ -n "$ino" && "$ino" != "0" ]] || continue

            if [[ "$LISTEN_ONLY" == "true" && "$proto" == udp* ]]; then
                # UDP has no LISTEN state; a socket without a peer is the
                # equivalent of a listening socket.
                [[ "${rhex#*:}" == "0000" ]] || continue
            elif [[ "$FILTER_STATE" == "true" ]]; then
                [[ -n "${want_state[$st]}" ]] || continue
            fi

            if [[ "$FILTER_PORT" == "true" ]]; then
                [[ -n "${want_port[${lhex#*:}]}" || -n "${want_port[${rhex#*:}]}" ]] || continue
            fi

            if [[ "$FILTER_USER" == "true" ]]; then
                [[ -n "${want_uid[$uid]}" ]] || continue
            fi

            rec_proto+=("$proto")
            rec_v6+=("$v6")
            rec_local+=("$lhex")
            rec_rem+=("$rhex")
            rec_state+=("$st")
            rec_uid+=("$uid")
            rec_inode+=("$ino")
            want[$ino]=1
        done
    } < "$file"
}

warned_ipv6=false
for table in "${TABLES[@]}"; do
    read -r file proto is_v6 <<< "$table"

    if [[ ! -r "$file" ]]; then
        if [[ "$is_v6" == "1" ]]; then
            # Missing IPv6 tables are not fatal
            if [[ "$warned_ipv6" == "false" ]]; then
                echo "Warning: $file not found. IPv6 connections will not be displayed." >&2
                warned_ipv6=true
            fi
            continue
        fi
        echo "Error: Cannot read $file. This script requires a Linux system with /proc filesystem." >&2
        exit 1
    fi

    read_conn_table "$file" "$proto" "$is_v6"
done

# Phase 2: map socket inodes to processes
declare -A pid_of=() cmd_of=()

for pid_dir in /proc/[0-9]*; do
    pid=${pid_dir##*/}
    [[ "$FILTER_PID" != "true" || -n "${want_pid[$pid]}" ]] || continue
    cmd=""

    # One readlink for all file descriptors of this process instead of one per
    # descriptor. Only the set of socket inodes matters, not which fd holds
    # them, so the link targets need no correlation back to their paths.
    while read -r link; do
        [[ "$link" == socket:\[*\] ]] || continue
        ino=${link#socket:\[}
        ino=${ino%\]}
        [[ -n "${want[$ino]}" ]] || continue

        # Resolve the command lazily: most processes own no matching socket at
        # all, and reading comm for them is pure overhead.
        if [[ -z "$cmd" ]]; then
            read -r cmd 2>/dev/null < "$pid_dir/comm" || break
            [[ -n "$cmd" ]] || break
        fi

        pid_of[$ino]=$pid
        cmd_of[$ino]=$cmd
    done < <(readlink "$pid_dir"/fd/* 2>/dev/null)
done

# ---------------------------------------------------------------------------
# Phase 3: join connections with process information
#
# The output columns are kept in parallel arrays rather than in delimited
# records: a command name may contain any byte, so there is no delimiter that
# is safe to split on afterwards.
#
# The user is taken from the socket's own UID field (as netstat does), not
# from the owning process, so it stays correct for processes that dropped
# privileges after opening the socket.
# ---------------------------------------------------------------------------

declare -A user_cache=()    # uid -> name, so getent runs once per distinct uid
declare -a c_proto c_cmd c_pid c_user c_local c_rem c_state

for i in "${!rec_inode[@]}"; do
    ino=${rec_inode[$i]}
    [[ -n "${pid_of[$ino]}" ]] || continue

    if [[ "${rec_v6[$i]}" == "1" ]]; then
        parse_addr6 "${rec_local[$i]}"; local_addr=$REPLY
        parse_addr6 "${rec_rem[$i]}";   remote_addr=$REPLY
    else
        parse_addr "${rec_local[$i]}"; local_addr=$REPLY
        parse_addr "${rec_rem[$i]}";   remote_addr=$REPLY
    fi

    uid=${rec_uid[$i]}
    if [[ -z "${user_cache[$uid]}" ]]; then
        entry=$(getent passwd "$uid")
        user_cache[$uid]=${entry%%:*}
        [[ -n "${user_cache[$uid]}" ]] || user_cache[$uid]=$uid
    fi

    c_proto+=("${rec_proto[$i]}")
    c_cmd+=("${cmd_of[$ino]}")
    c_pid+=("${pid_of[$ino]}")
    c_user+=("${user_cache[$uid]}")
    c_local+=("$local_addr")
    c_rem+=("$remote_addr")
    c_state+=("${states[${rec_state[$i]}]:-UNKNOWN_${rec_state[$i]}}")
done

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

# Calculate dynamic column widths into the global array W
declare -a W

calculate_widths() {
    local i

    # Initialize with header lengths
    W=(7 3 4 13 14 5 5)

    for i in "${!c_cmd[@]}"; do
        [[ ${#c_cmd[$i]}   -gt ${W[0]} ]] && W[0]=${#c_cmd[$i]}
        [[ ${#c_pid[$i]}   -gt ${W[1]} ]] && W[1]=${#c_pid[$i]}
        [[ ${#c_user[$i]}  -gt ${W[2]} ]] && W[2]=${#c_user[$i]}
        [[ ${#c_local[$i]} -gt ${W[3]} ]] && W[3]=${#c_local[$i]}
        [[ ${#c_rem[$i]}   -gt ${W[4]} ]] && W[4]=${#c_rem[$i]}
        [[ ${#c_state[$i]} -gt ${W[5]} ]] && W[5]=${#c_state[$i]}
        [[ ${#c_proto[$i]} -gt ${W[6]} ]] && W[6]=${#c_proto[$i]}
    done

    return 0
}

# Output in table format
output_table() {
    local i
    calculate_widths

    if [[ "$SHOW_PROTO" == "true" ]]; then
        printf "%-${W[6]}s %-${W[0]}s %-${W[1]}s %-${W[2]}s %-${W[3]}s %-${W[4]}s %s\n" \
            "PROTO" "COMMAND" "PID" "USER" "LOCAL ADDRESS" "REMOTE ADDRESS" "STATE"
        for i in "${!c_cmd[@]}"; do
            printf "%-${W[6]}s %-${W[0]}s %-${W[1]}s %-${W[2]}s %-${W[3]}s %-${W[4]}s %s\n" \
                "${c_proto[$i]}" "${c_cmd[$i]}" "${c_pid[$i]}" "${c_user[$i]}" \
                "${c_local[$i]}" "${c_rem[$i]}" "${c_state[$i]}"
        done
        return
    fi

    printf "%-${W[0]}s %-${W[1]}s %-${W[2]}s %-${W[3]}s %-${W[4]}s %s\n" \
        "COMMAND" "PID" "USER" "LOCAL ADDRESS" "REMOTE ADDRESS" "STATE"

    for i in "${!c_cmd[@]}"; do
        printf "%-${W[0]}s %-${W[1]}s %-${W[2]}s %-${W[3]}s %-${W[4]}s %s\n" \
            "${c_cmd[$i]}" "${c_pid[$i]}" "${c_user[$i]}" \
            "${c_local[$i]}" "${c_rem[$i]}" "${c_state[$i]}"
    done
}

# Output in CSV format
output_csv() {
    local i

    # Print header
    if [[ "$SHOW_PROTO" == "true" ]]; then
        echo "PROTO,COMMAND,PID,USER,LOCAL ADDRESS,REMOTE ADDRESS,STATE"
    else
        echo "COMMAND,PID,USER,LOCAL ADDRESS,REMOTE ADDRESS,STATE"
    fi

    # Print connections, escaping quotes by doubling them
    for i in "${!c_cmd[@]}"; do
        [[ "$SHOW_PROTO" == "true" ]] && printf '"%s",' "${c_proto[$i]//\"/\"\"}"
        printf '"%s","%s","%s","%s","%s","%s"\n' \
            "${c_cmd[$i]//\"/\"\"}" "${c_pid[$i]//\"/\"\"}" "${c_user[$i]//\"/\"\"}" \
            "${c_local[$i]//\"/\"\"}" "${c_rem[$i]//\"/\"\"}" "${c_state[$i]//\"/\"\"}"
    done
}

# Escape a string for JSON -> $REPLY
json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\r'/\\r}
    REPLY=$s
}

# Output in JSON format
output_json() {
    local i first=true cmd user local_addr remote_addr state

    echo "["

    for i in "${!c_cmd[@]}"; do
        # Add comma before all but first entry
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi

        json_escape "${c_cmd[$i]}";   cmd=$REPLY
        json_escape "${c_user[$i]}";  user=$REPLY
        json_escape "${c_local[$i]}"; local_addr=$REPLY
        json_escape "${c_rem[$i]}";   remote_addr=$REPLY
        json_escape "${c_state[$i]}"; state=$REPLY

        printf '  {\n'
        [[ "$SHOW_PROTO" == "true" ]] && printf '    "proto": "%s",\n' "${c_proto[$i]}"
        printf '    "command": "%s",\n    "pid": %s,\n    "user": "%s",\n    "local_address": "%s",\n    "remote_address": "%s",\n    "state": "%s"\n  }' \
            "$cmd" "${c_pid[$i]}" "$user" "$local_addr" "$remote_addr" "$state"
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
