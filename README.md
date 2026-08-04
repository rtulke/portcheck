# pcng - Port Check Next Generation

A lightweight, dependency-free Bash script to display active TCP and TCP6 network connections with detailed process information on Linux systems.

## Features

- **Zero Dependencies** - Uses only Bash and standard Unix tools
- **Multiple Output Formats** - Table, CSV, and JSON support
- **IPv4 & IPv6 Support** - Handles both TCP and TCP6 connections
- **Dynamic Table Widths** - Automatically adjusts column widths
- **RFC-Compliant IPv6** - Proper IPv6 address compression (RFC 5952)
- **Performance Optimized** - Single-pass processing for efficiency
- **Robust Error Handling** - Graceful handling of missing features

## Requirements

- Linux system with `/proc` filesystem
- Bash 4.0 or higher
- Standard Unix tools: `cat`, `awk`, `getent`, `grep`, `sed`, `readlink`, `tail`, `cut`

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/portcheck.git
cd portcheck

# Make the script executable
chmod +x pcng.sh
```

```bash
Usage: pcng.sh [OPTIONS]

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
  pcng.sh                           # Default table output
  pcng.sh --format=csv              # CSV output
  pcng.sh --format=json             # JSON output
  pcng.sh --ipv6-format=full        # Full IPv6 addresses
  pcng.sh -l                        # Listening TCP sockets only
  pcng.sh --proto=all -l            # Listening TCP and UDP sockets
  pcng.sh --port=80,443             # HTTP/HTTPS connections
  pcng.sh --user=root --state=ESTABLISHED
```

## TCP Connection States

The script recognizes all standard TCP states:

- `ESTABLISHED` - Active connection
- `LISTEN` - Listening for incoming connections
- `SYN_SENT` - Attempting to establish connection
- `SYN_RECV` - Received connection request
- `FIN_WAIT1`, `FIN_WAIT2` - Connection closing
- `TIME_WAIT` - Waiting after close
- `CLOSE` - Connection closed
- `CLOSE_WAIT` - Remote endpoint has shut down
- `LAST_ACK` - Waiting for connection termination
- `CLOSING` - Both sides closing simultaneously

## License

This project is open source and available under the MIT License.

