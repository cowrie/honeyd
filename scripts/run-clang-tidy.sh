#!/bin/bash
# Script to run clang-tidy on honeyd source files

set -e

if [ ! -f build/compile_commands.json ]; then
    echo "Error: compile_commands.json not found in build/"
    echo "Run: cd build && cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .."
    exit 1
fi

# Find all C source files, excluding generated and third-party code
find . -name '*.c' \
    -not -path './build/*' \
    -not -path './compat/*' \
    -not -path './dpkt/*' \
    -not -path './pypcap/*' \
    -not -path './webserver/*' \
    | xargs clang-tidy -p build "$@"
