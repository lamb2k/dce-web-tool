#!/bin/bash
set -euo pipefail
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
git apply --include='core/network/browser_ethernet_queue.h' "$here/browser-ethernet.patch"
g++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined -I "$work/core/network" "$here/tests/queue_test.cpp" -o queue-test
./queue-test
