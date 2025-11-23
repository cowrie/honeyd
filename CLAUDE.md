# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About Honeyd

Honeyd is a small daemon that creates virtual hosts on a network. It can simulate thousands of virtual machines with different OS personalities, network services, and routing topologies. Used for network simulation, honeypots, and security research.

## Build System

The project uses **CMake** (modern build system, as of recent migration from autotools).

**IMPORTANT**: The build directory is `build/` at the project root. Always run cmake commands from this directory, not from the project root.

### Building from Source

```bash
# Initial configuration (from project root)
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build (from build/ directory)
cmake --build .

# Or use make directly
make -j4

# Install (requires root)
sudo make install
```

### Development Workflow

When working on the code, you're typically in the `build/` directory:

```bash
# Check current directory
pwd  # Should show: /home/michel/src/honeyd/build

# Rebuild after code changes
cmake --build .

# Clean build
cmake --build . --target clean

# Rebuild specific target
cmake --build . --target honeyd

# View build warnings/errors
cmake --build . 2>&1 | less

# Check for specific types of warnings
cmake --build . 2>&1 | grep "warning:"
cmake --build . 2>&1 | grep "error:"
```

### CMake Targets

Main executables:
- `honeyd` - Main daemon
- `honeydctl` - Control utility
- `honeydstats` - Statistics analyzer
- `hsniff` - Packet sniffer

Libraries:
- `libhoneyd` - Overload library

Build specific target:
```bash
cmake --build . --target honeyd
cmake --build . --target hsniff
```

### Build Outputs

- `honeyd` - Main daemon that creates virtual hosts
- `honeydctl` - Control utility for managing running honeyd instance
- `honeydstats` - Statistics analyzer for honeyd logs
- `hsniff` - Packet sniffer for honeyd traffic analysis
- `libhoneyd.a` - Library for overloading functions

### Dependencies

Required libraries:
- libevent - event notification
- libdumbnet (libdnet) - packet creation and manipulation
- libpcap - packet capture
- libreadline - command line editing
- zlib - compression
- flex/bison - parser generation

Install on Debian/Ubuntu:
```bash
sudo apt-get install cmake libevent-dev libdumbnet-dev libpcap-dev \
    libreadline-dev zlib1g-dev flex bison
```

### Building Debian Packages

```bash
# Build unsigned packages
dpkg-buildpackage -us -uc -b

# Packages will be in parent directory:
# - honeyd_*.deb (main package with binaries and config files)
# - honeyd-common_*.deb (scripts and webserver)
# - honeyd-dbgsym_*.deb (debug symbols)
```

## Running Honeyd

Honeyd requires root privileges to create raw sockets and capture packets.

```bash
# Run with configuration file
sudo honeyd -d -f /etc/honeyd/honeyd.conf 10.0.0.0/8

# Common options:
# -d              Debug mode (foreground, verbose logging)
# -f <file>       Configuration file
# -i <interface>  Network interface to use
# -u <uid>        Drop privileges to this user
# -g <gid>        Drop privileges to this group
# -l <logfile>    Log packets to file
```

Configuration files are installed to `/etc/honeyd/` when using the Debian package, or `/usr/local/share/honeyd/` for manual installs.

## Architecture Overview

### Core Components

**Main Daemon (honeyd.c)**
- Event-driven architecture using libevent
- Manages virtual host lifecycle and packet routing
- Coordinates all subsystems

**Configuration System**
- `parse.y` + `lex.l` - Bison/Flex parser for configuration files
- `config.c` - Configuration management
- `command.c` - Command interpreter for honeydctl
- `template.c` - Virtual host templates

**Network Stack**
- `interface.c` - Network interface management and packet capture (uses pcap_findalldevs)
- `network.c` - IP routing and forwarding
- `arp.c` - ARP simulation for virtual hosts
- `ethernet.c` - Ethernet frame handling
- `gre.c` - GRE tunnel support
- `dhcpclient.c` - DHCP client for dynamic addressing

**Protocol Handlers**
- `tcp.c` - TCP state machine and connection tracking
- `udp.c` - UDP connection handling
- `router.c` - Routing table and network topology
- `ipfrag.c` - IP fragmentation and reassembly

**OS Personality Emulation**
- `personality.c` - OS fingerprint database management
- `osfp.c` - OS fingerprinting integration
- `pf_osfp.c` + `pfctl_osfp.c` - pf OS fingerprinting
- `xprobe_assoc.c` - Xprobe2 fingerprint database

Database files in `/etc/honeyd/` or `/usr/share/honeyd/`:
- `nmap-os-db` - Nmap OS fingerprints (must be compatible version)
- `pf.os` - pf OS fingerprints
- `xprobe2.conf` - Xprobe2 signatures
- `nmap.assoc` - Association data
- `nmap-mac-prefixes` - MAC address vendor prefixes

**Service Emulation**
- `subsystem.c` + `hooks.c` - External script execution
- `plugins.c` + `plugins_config.c` - Plugin system
- Scripts in `/usr/share/honeyd/scripts/` - Service simulators (Perl, Python, shell)

**Monitoring and Logging**
- `tagging.c` + `untagging.c` - Packet tagging for analysis
- `stats.c` - Statistics collection
- `histogram.c` - Data distribution analysis
- `log.c` - Logging infrastructure
- `rrdtool.c` - RRDtool integration for graphing

**Utilities**
- `util.c` - Common utility functions
- `pool.c` - Memory pool management
- `ui.c` - User interface helpers

### Key Data Structures

- **Template**: Defines a virtual host configuration (OS personality, services, network settings)
- **TCP/UDP connection trees**: SPLAY trees for connection tracking
- **Interface list**: TAILQ of active network interfaces
- **Routing table**: Network topology and path simulation

### Configuration File Format

The configuration language defines templates and binds them to IP addresses:

```
create <template-name>
set <template> personality "OS Name"
set <template> default tcp action <block|open|closed|reset>
add <template> tcp port <port> <script>
add <template> udp port <port> <script>
bind <ip-address> <template>
```

Example in `config.sample` shows Windows template bound to IP address.

## CI/CD

GitHub Actions workflows in `.github/workflows/`:

- `ci.yml` - Main build and test workflow
- `cppcheck.yml` - Static analysis with cppcheck (uses `-i` for excludes, `--error-exitcode=1`)
- `clang-tidy.yml` - Clang-Tidy analysis (shows first 50 issues in log, full report in artifact)
- `debian-package.yml` - Debian package builds (runs on main branch and tags)

All workflows run on push to main branch and pull requests.

## Recent Development Work (by Claude Code)

### Python 3 Migration (2025-01-22)
All Python code has been migrated from Python 2 to Python 3.13:

**C Extensions (pyextend.c, pydataprocessing.c, pydatahoneyd.c)**:
- Migrated Python C API from Python 2 to Python 3
- `PyString_*` → `PyBytes_*` for binary data, `PyUnicode_*` for text
- `Py_InitModule` → `PyModule_Create` with `PyModuleDef` structures
- All size parameters: `int` → `Py_ssize_t`
- Replaced deprecated `Py_GetPath/PySys_SetPath` with `PyRun_SimpleString`
- Updated embedded test code to Python 3 syntax

**Web Server (webserver/)**:
- server.py: Updated imports, replaced execfile(), fixed print syntax
- support.py: Fixed urllib/cgi imports, removed has_key(), fixed integer division
- htmltmpl.py: Extensive syntax migration using pyupgrade and ast-grep

**Scripts (scripts/)**:
- Migrated all utility scripts to Python 3

**Regression Tests (regress/)**:
- Updated all test files for Python 3 compatibility
- Fixed print statements, integer division, repr syntax
- Added raw strings for regex patterns
- Note: Tests still broken per IMPORTANT_NOTES.txt (requires functional fixes beyond syntax)

**Dependencies**:
- Removed vendored dpkt library (48 files from 2005, Python 2 only)
- Added requirements.txt with modern external dependencies: dpkt>=1.9.8, ruff>=0.1.0, pyupgrade>=3.15.0
- Integrated ruff linting into GitHub Actions CI/CD

**CMake Integration**:
- Added conditional Python 3 detection and compilation
- Python extensions now properly linked when Python 3 is available

## Commit Message Guidelines

- Do not mention Claude, AI assistants, or automated tools in commit messages
- No emojis or smileys in commit messages
- Use conventional commit style: imperative mood, concise summary, detailed body if needed
- Focus on what changed and why, not how it was created

## Code Conventions

- C code follows BSD/OpenBSD style
- Uses libevent for async I/O, not raw select/poll
- Network byte order handling with dnet library
- Error logging via syslog
- Configuration parsing is done at startup, runtime changes via honeydctl

## Known Issues and TODOs

- **Regression tests are currently broken** - see `regress/IMPORTANT_NOTES.txt`. Python 3 syntax migration is complete, but tests need functional rewrites for modern Honeyd.
- nmap-os-db compatibility: Must use older version compatible with honeyd 1.6e parser. Modern nmap databases (7.94.2+) cause parsing failures.

## Important File Paths

Configuration and data files use CMake variables:
- `PATH_HONEYDDATA` - Data files location (default: `/usr/share/honeyd/`)
- `PATH_HONEYDLIB` - Library location (default: `/usr/lib/honeyd/`)
- `PATH_HONEYDINCLUDE` - Include files (default: `/usr/include/honeyd/`)

These are set in `CMakeLists.txt` and should never be hardcoded with absolute paths.

## Development Environment

### Virtual Environment

The project uses direnv for environment management. The Python virtual environment is located in `.direnv/python-3.13.5/`.

To activate manually (if direnv is not active):
```bash
source .direnv/python-3.13.5/bin/activate
```

### Code Refactoring Tools

**IMPORTANT**: When performing code refactoring or systematic code changes, **always prefer ast-grep over sed/awk**.

ast-grep is available in the virtual environment and provides structural code understanding:
```bash
# Activate environment first
source .direnv/python-3.13.5/bin/activate

# Example: Find all atoi() calls
ast-grep --pattern 'atoi($$$)'

# Example: Replace pattern
ast-grep --pattern 'atoi($ARG)' --rewrite 'safe_atoi($ARG, &result, "context")' --update-all
```

**Why ast-grep over sed**:
- Understands code structure (AST-based)
- Handles variable whitespace and formatting
- Avoids false positives in comments/strings
- More reliable for C code transformations

## Development Notes

- When modifying the parser, regenerate with bison/flex (handled automatically by CMake)
- Configuration file changes require daemon restart
- OS personality databases must match the expected format version
- Virtual hosts require manual cleanup on daemon exit (cleanup incomplete in some error paths)
- Network interface must support promiscuous mode for packet capture
