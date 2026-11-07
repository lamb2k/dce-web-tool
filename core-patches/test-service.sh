#!/bin/bash
set -euo pipefail
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
git apply --include='core/network/browser_ethernet*' "$here/browser-ethernet.patch"
g++ -std=c++17 -D__EMSCRIPTEN__ -Wall -Wextra -Werror -fsanitize=address,undefined -I "$work/core/network" -I "$here/tests/shims" "$here/tests/service_test.cpp" -o service-test
./service-test
