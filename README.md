# pcng - Port Check Next Generation

A lightweight, dependency-free Bash script to display active TCP and TCP6 network connections with detailed process information on Linux systems.

## Features

- 🚀 **Zero Dependencies** - Uses only Bash and standard Unix tools
- 📊 **Multiple Output Formats** - Table, CSV, and JSON support
- 🌐 **IPv4 & IPv6 Support** - Handles both TCP and TCP6 connections
- 🎨 **Dynamic Table Widths** - Automatically adjusts column widths
- 🔧 **RFC-Compliant IPv6** - Proper IPv6 address compression (RFC 5952)
- ⚡ **Performance Optimized** - Single-pass processing for efficiency
- 🛡️ **Robust Error Handling** - Graceful handling of missing features

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

# Run it
./pcng.sh
```

## Usage

```bash
./pcng.sh [OPTIONS]
```

### Options

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--format` | `table`, `csv`, `json` | `table` | Output format |
| `--ipv6-format` | `compressed`, `full` | `compressed` | IPv6 address display format |
| `-h`, `--help` | - | - | Show help message |

### Examples

**Default table output:**
```bash
./pcng.sh
```
```
COMMAND   PID       USER                 LOCAL ADDRESS         REMOTE ADDRESS        STATE
sshd      1234      root                 0.0.0.0:22            0.0.0.0:0             LISTEN
chrome    5678      user                 192.168.1.100:54321   172.217.16.46:443     ESTABLISHED
```

**CSV format for parsing:**
```bash
./pcng.sh --format=csv
```
```csv
COMMAND,PID,USER,LOCAL ADDRESS,REMOTE ADDRESS,STATE
"sshd","1234","root","0.0.0.0:22","0.0.0.0:0","LISTEN"
"chrome","5678","user","192.168.1.100:54321","172.217.16.46:443","ESTABLISHED"
```

**JSON format for APIs:**
```bash
./pcng.sh --format=json
```
```json
[
  {
    "command": "sshd",
    "pid": 1234,
    "user": "root",
    "local_address": "0.0.0.0:22",
    "remote_address": "0.0.0.0:0",
    "state": "LISTEN"
  },
  {
    "command": "chrome",
    "pid": 5678,
    "user": "user",
    "local_address": "192.168.1.100:54321",
    "remote_address": "172.217.16.46:443",
    "state": "ESTABLISHED"
  }
]
```

**Full IPv6 addresses (no compression):**
```bash
./pcng.sh --ipv6-format=full
```

**Compressed IPv6 addresses (RFC 5952):**
```bash
./pcng.sh --ipv6-format=compressed
```
```
# Example: 0:0:0:0:0:0:0:1 becomes ::1
# Example: 2001:0db8:0000:0000:0000:0000:0000:0001 becomes 2001:db8::1
```

## How It Works

1. **Process Scanning**: Scans `/proc/[0-9]*/` for all running processes
2. **Socket Mapping**: Maps socket inodes to process information (PID, command, user)
3. **Connection Parsing**: Reads `/proc/net/tcp` and `/proc/net/tcp6` for active connections
4. **Data Collection**: Collects all connection data in memory
5. **Output Formatting**: Formats and displays data based on selected format

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

## Permissions

- **As regular user**: Shows only your own processes' connections
- **As root**: Shows all connections from all users

When not running as root, you'll see a note:
```
Note: Not running as root. Only connections from your own processes will be visible.
```

## Performance

The script is optimized for performance:
- Single-pass processing (TCP and TCP6 processed together)
- Direct `/proc` filesystem access (no external commands for parsing)
- Efficient inode mapping to avoid redundant lookups

## Troubleshooting

**Error: Cannot read /proc/net/tcp**
- You're not on a Linux system with `/proc` filesystem
- This script requires Linux

**Warning: /proc/net/tcp6 not found**
- Your system doesn't have IPv6 support enabled
- Only IPv4 connections will be displayed

**No connections shown**
- Run as root to see all connections: `sudo ./pcng.sh`
- Or check if there are any active connections: `ls -la /proc/net/tcp*`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Changelog

### v2.0.0 (2026-01-03)
- Added multiple output formats (table, CSV, JSON)
- Implemented dynamic column widths for table output
- Added RFC 5952-compliant IPv6 compression
- Added `--ipv6-format` option for full/compressed IPv6 display
- Improved error handling and validation
- Performance optimization: single-pass processing
- Added comprehensive help message
- Better handling of missing IPv6 support

### v1.0.0
- Initial release with basic TCP/TCP6 monitoring
- IPv6 address parsing support

## Credits

Developed and maintained by the portcheck community.
