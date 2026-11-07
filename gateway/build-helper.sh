#!/usr/bin/env bash
# Build only from pinned source + privately extracted packages. Never install globally.
set -euo pipefail
: "${HALO_GATEWAY_BUILD_ROOT:?Set private task build directory}"
task_root=$(realpath "$HALO_GATEWAY_BUILD_ROOT")
source_dir="$task_root/libslirp"
deps="$task_root/deps"
here=$(cd "$(dirname "$0")" && pwd)
# The deps tree must come from exactly these packages. Unpack only after they pass.
: "${HALO_GATEWAY_DEBS:?Set the directory holding the private .deb files}"
python3 "$here/verify-debs.py" "$here/dependencies.json" "$HALO_GATEWAY_DEBS"
pin=9c744e1e52aa0d9646ed91d789d588696292c21e
test "$(git -C "$source_dir" rev-parse HEAD)" = "$pin"
test -z "$(git -C "$source_dir" status --porcelain)"
for package in "$HALO_GATEWAY_DEBS"/*.deb; do dpkg-deb -x "$package" "$deps"; done
export PKG_CONFIG_LIBDIR="$deps/usr/lib/x86_64-linux-gnu/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$deps"
if [ ! -f "$task_root/build/build.ninja" ]; then
  meson setup "$task_root/build" "$source_dir" --default-library=static
fi
ninja -C "$task_root/build"
cc -std=c11 -O2 -Wall -Wextra -Werror -I"$source_dir/src" -I"$task_root/build" \
  "$here/gateway.c" "$task_root/build/libslirp.a" \
  -L"$deps/usr/lib/x86_64-linux-gnu" -Wl,-rpath,"$deps/usr/lib/x86_64-linux-gnu" \
  -lglib-2.0 -o "${HALO_GATEWAY_OUTPUT:-$task_root/gateway}"
printf 'Built native helper; no server started.\n'
