# pcng - Port Check Next Generation

A lightweight, dependency-free Bash script that lists active TCP and UDP
connections together with the owning process, reading everything from `/proc`.
No `netstat`, no `ss`, no `lsof`.

```
COMMAND  PID  USER     LOCAL ADDRESS       REMOTE ADDRESS       STATE
sshd     1234 root     0.0.0.0:22          0.0.0.0:0            LISTEN
nginx    2201 www-data 0.0.0.0:80          0.0.0.0:0            LISTEN
chrome   5678 user     192.168.1.100:54321 172.217.16.46:443    ESTABLISHED
postgres 3310 postgres [2001:db8::1]:5432  [2001:db8::42]:41288 ESTABLISHED
```

## Features

- **Zero dependencies** - Bash plus `readlink`, `getent` and `cat`
- **Machine-readable output** - table, CSV and JSON
- **IPv4 and IPv6** - TCP, TCP6, UDP and UDP6
- **Filters** - by state, port, user and PID, applied before the expensive lookup
- **RFC 5952 IPv6** - zero-run compression and IPv4-mapped mixed notation
- **Fast** - no subshells or external commands in the hot paths

## Requirements

- Linux with a `/proc` filesystem
- Bash 4.0 or higher (associative arrays)
- `readlink`, `getent`, `cat`

## Installation

```bash
git clone https://github.com/yourusername/portcheck.git
cd portcheck
chmod +x pcng.sh
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
| `--proto` | `tcp`, `udp`, `all` | `tcp` | Protocol to display |
| `-l`, `--listen` | - | - | Only listening sockets |
| `--state` | comma separated state names | - | Only these connection states |
| `--port` | comma separated ports | - | Only these ports (local or remote) |
| `--user` | comma separated names or UIDs | - | Only sockets owned by these users |
| `--pid` | comma separated PIDs | - | Only sockets of these processes |
| `-h`, `--help` | - | - | Show help message |

Filters combine with AND:

```bash
./pcng.sh -l                                  # listening TCP sockets
./pcng.sh --proto=all -l                      # listening TCP and UDP sockets
./pcng.sh --port=80,443                       # HTTP/HTTPS, local or remote port
./pcng.sh --user=root --state=ESTABLISHED     # established root connections
./pcng.sh --pid=1234 --format=json            # one process, as JSON
```

`-l` is shorthand for `--state=LISTEN`. UDP has no LISTEN state, so for UDP
sockets it selects those without a peer, which is the equivalent condition.

State names are case insensitive; an unknown name is rejected with the list of
valid ones.

### Output formats

**Table** (default) sizes every column to its widest value:

```bash
./pcng.sh
```
```
COMMAND  PID  USER     LOCAL ADDRESS       REMOTE ADDRESS       STATE
sshd     1234 root     0.0.0.0:22          0.0.0.0:0            LISTEN
nginx    2201 www-data 0.0.0.0:80          0.0.0.0:0            LISTEN
chrome   5678 user     192.168.1.100:54321 172.217.16.46:443    ESTABLISHED
postgres 3310 postgres [2001:db8::1]:5432  [2001:db8::42]:41288 ESTABLISHED
```

**CSV** quotes every field and doubles embedded quotes:

```bash
./pcng.sh --format=csv
```
```csv
COMMAND,PID,USER,LOCAL ADDRESS,REMOTE ADDRESS,STATE
"sshd","1234","root","0.0.0.0:22","0.0.0.0:0","LISTEN"
"nginx","2201","www-data","0.0.0.0:80","0.0.0.0:0","LISTEN"
"chrome","5678","user","192.168.1.100:54321","172.217.16.46:443","ESTABLISHED"
```

**JSON** emits `pid` as a number, everything else as strings:

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
    "command": "nginx",
    "pid": 2201,
    "user": "www-data",
    "local_address": "0.0.0.0:80",
    "remote_address": "0.0.0.0:0",
    "state": "LISTEN"
  }
]
```

An empty result is a valid empty array, so `jq` and friends need no special
casing.

### Protocols

`--proto` selects which tables are read. With `--proto=all` an extra `PROTO`
column is added to every output format:

```bash
./pcng.sh --proto=all -l
```
```
PROTO COMMAND      PID  USER    LOCAL ADDRESS REMOTE ADDRESS STATE
tcp   sshd         1234 root    0.0.0.0:22    0.0.0.0:0      LISTEN
tcp6  sshd         1234 root    [::]:22       [::]:0         LISTEN
udp   chronyd      900  _chrony 0.0.0.0:123   0.0.0.0:0      CLOSE
udp6  avahi-daemon 700  avahi   [::]:5353     [::]:0         CLOSE
```

Without `--proto=all` the output is byte-for-byte what it was before the column
existed, so existing CSV/JSON consumers are unaffected. Note that the default
`--proto=tcp` merges TCP and TCP6 rows without labelling them.

### IPv6 formatting

```bash
./pcng.sh --ipv6-format=compressed   # default
./pcng.sh --ipv6-format=full
```

```
# 0:0:0:0:0:0:0:1                          becomes ::1
# 2001:0db8:0000:0000:0000:0000:0000:0001  becomes 2001:db8::1
# 0:0:0:0:0:ffff:7f00:1                    becomes ::ffff:127.0.0.1
```

The IPv4-mapped mixed notation (RFC 5952 section 5) applies to the compressed
format only. `full` means uncompressed, not zero-padded: groups still print
without leading zeros.

## How it works

1. **Connection parsing** - reads `/proc/net/tcp{,6}` and `/proc/net/udp{,6}`, applies the state, port and user filters directly on the raw hex fields, and collects the socket inodes worth resolving
2. **Socket mapping** - scans `/proc/[0-9]*/fd/` for `socket:[inode]` links, resolving the command name only for processes that own one of those inodes
3. **Join** - combines connections with process information, decodes addresses and resolves UIDs to user names
4. **Output** - formats the result according to `--format`

Connections whose socket inode cannot be traced to a process are omitted, which
is why an unprivileged run shows only a few rows.

## Connection states

- `ESTABLISHED` - active connection
- `LISTEN` - listening for incoming connections
- `SYN_SENT` - attempting to establish a connection
- `SYN_RECV`, `NEW_SYN_RECV` - received a connection request
- `FIN_WAIT1`, `FIN_WAIT2` - connection closing
- `TIME_WAIT` - waiting after close
- `CLOSE` - connection closed
- `CLOSE_WAIT` - remote endpoint has shut down
- `LAST_ACK` - waiting for connection termination
- `CLOSING` - both sides closing simultaneously

Unknown codes print as `UNKNOWN_<code>` rather than leaving the column blank.
UDP sockets reuse the same field: the kernel reports `CLOSE` for unconnected
and `ESTABLISHED` for connected sockets, and that value is shown as-is.

## Permissions

- **As a regular user**: only your own processes' connections
- **As root**: all connections

```
Note: Not running as root. Only connections from your own processes will be visible.
```

The `USER` column shows the owner of the socket, i.e. the UID recorded in
`/proc/net/*`, which is what `netstat` reports. A daemon that binds as root and
then drops privileges therefore stays `root`.

## Performance

- Direct `/proc` access, parsed with Bash parameter expansion only
- Connection tables are read first, so the process scan resolves nothing that
  no connection refers to
- One `readlink` per process instead of one per file descriptor
- Filters run before the process scan, so excluded sockets cost nothing
- The only commands forked at runtime are one `readlink` per process and one
  `getent` per distinct UID

## Troubleshooting

**Error: Cannot read /proc/net/tcp**
- Not a Linux system, or `/proc` is not mounted. The script requires Linux.

**Warning: /proc/net/tcp6 not found**
- IPv6 is disabled on this system; only IPv4 connections are shown. Missing
  IPv6 tables are never fatal.

**No connections shown**
- Run as root to see all connections: `sudo ./pcng.sh`
- Check whether any exist at all: `ls -la /proc/net/tcp*`
- Note that sockets without an owning process (e.g. `TIME_WAIT`) are skipped

**Unexpected empty result with filters**
- Filters combine with AND. `--state=LISTEN --port=443` matches only sockets
  that are both.
