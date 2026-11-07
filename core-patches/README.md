# Browser Ethernet core patch (qualification checkpoint)

Emscripten-only Service replaces native Pico/DCNet selection. Guest TX goes through owned JS bytes; RX copies into a fixed queue and reaches BBA only at retro_run. Reset, unload, deinit, save-state restore and BBA teardown invalidate generation and close transport. Transport stop/configure preserve an already started BBA service; only actual service/core teardown clears that latch. RX/TX require both device-start and current lease. Stop callbacks cannot reconfigure a lease or recursively notify. Native desktop path unchanged. Dreamcast RAM/VRAM/AICA cost0B.

Measured core state50448B (RX queue48928B, staging1514B, flags/counter6B before linker alignment). RX payload48448B; JS TX payload at most48448B plus object overhead.32frames/direction,48KiB direction ceiling,1000ms age,65536B WebSocket bufferedAmount ceiling,10s connect timeout. Hidden browser buffers remain unmeasured. Initial WASM memory256MiB; this is separate from Dreamcast RAM.

One binary WSS message per Ethernet frame14..1514B, no FCS or envelope; ARP/IPv4 only. Lease HTTP metadata includes websocketPath and expiresAt. Same-origin authenticated Worker/gateway owns authorization, source/destination ACLs, mapping and expiry. Gateway-authenticated does not mean DHCP, game admission or gameplay. Adapter capability stays false. Core configure returns0 if called during stop notification; callers fail closed. Diagnostic metric7 reports device-start latch, metric8 reports transport readiness; neither is guest DHCP or admission.

## Evidence and remaining gate

Reconnect-r2 isolated compile/link and actual WASM export smoke PASS: inactive-device RX refused, nested stop notifies once, reentrant configure returns0, and a new lease cannot reactivate a stopped device. Known state50448B measured through the new binary. The earlier r1 binary also passed its32frame ring bound. Both receipts remain distinct in pins.json. Portable sanitized queue and production-service lifecycle tests plus6 adapter tests PASS. Reconnect tests cover start before lease, new lease without another device start, stale generations, true core teardown, and same-callback stop reentry. Actual authenticated same-origin Worker WebSocket sent42B ARP request and received matching64B reply from native gateway. That fixture was direct browser transport, not emulated guest traffic.

Earlier r1 core booted exact b8 title and accepted onboarding/main/multiplayer/HOST controls. Reconnect-r2 has not repeated game boot or guest-device traffic qualification. Bounded HOST observation stayed CHECKING GAME DATA;0Ethernet frames. That image predates BBA registration fix0672aaba. Actual guest DHCP and service/device traffic need a new qualified image. No paired automation, Host/Join gameplay or native crossplay acceptance. Existing core WebGL capability warnings and audio underruns remain separate open issues. Two existing libc++ streambuf linker signature warnings remain; undefined-symbol permissiveness inherited from upstream build is not networking evidence.

The staged adapter files remain historical reproduction inputs. Production
`public/browser-ethernet.mjs` now attaches through the bounded lease lifecycle in
`public/guest-network.mjs`. Actual b9 boot established gateway readiness before
guest frames, but did not reach the intended guest JOIN path. Guest DHCP/TLS and
game admission remain unqualified; guestNetwork stays false. No core binary
change was needed for this frontend attachment.

## Reproduction

Use Linux/WSL, git, CMake, make, Python3, Node and pinned Emscripten3.1.74. Choose a fresh disposable workspace. PATCHES names this checked-out core-patches directory; WORK is an operator-chosen build directory. Never point source/build/output/cache at the existing tested runtime. All source repositories retain their licenses; see NOTICE.md.

```sh
# Set PATCHES, WORK and EMSDK_ROOT to your own locations first.
export PATCHES WORK EMSDK_ROOT
mkdir -p "$WORK"
git clone --recursive https://github.com/flyinghead/flycast.git "$WORK/source"
git -C "$WORK/source" checkout 2c48c0188a2afc158b02b6d1865d898756a03071
git -C "$WORK/source" submodule update --init --recursive
git clone https://github.com/nasomers/flycast-wasm.git "$WORK/wasm-foundation"
git -C "$WORK/wasm-foundation" checkout 16e9c7b4b7065a4bd42e7490e8aab3e9283d5415
git clone https://github.com/EmulatorJS/RetroArch.git "$WORK/EJS-RetroArch"
git -C "$WORK/EJS-RetroArch" checkout ed3265745eccec99b48f99e2a2ffc8a6a93823bb
# baseline-wasm.patch is COMPLETE against pinned Flycast; do not also apply upstream's WASM patch.
git -C "$WORK/source" apply --ignore-space-change "$PATCHES/baseline-wasm.patch"
mkdir -p "$WORK/source/core/rec-wasm"
for name in fly_instrument.h rec_wasm.cpp wasm_emit.h wasm_module_builder.h; do
  cp "$WORK/wasm-foundation/patches/$name" "$WORK/source/core/rec-wasm/$name"
done
git -C "$WORK/source" apply --ignore-space-change "$PATCHES/browser-ethernet.patch"
git -C "$WORK/source" apply --ignore-space-change "$PATCHES/browser-vmu.patch"
git -C "$WORK/source" apply --ignore-space-change "$PATCHES/browser-vmu-guard.patch"
source "$EMSDK_ROOT/emsdk_env.sh"
export EM_CACHE="$WORK/emscripten-cache" EMCC_CORES=2 BINARYEN_CORES=2
# Fresh private cache; preserve SDK cache.
cp -a "$EMSDK_ROOT/upstream/emscripten/cache" "$EM_CACHE"
# Build the pinned frontend's object target without attempting its separate final link.
printf 'include Makefile.emulatorjs\n.PHONY: objects\nobjects: $(RARCH_OBJ)\n' > "$WORK/EJS-RetroArch/Makefile.core-objects"
(cd "$WORK/EJS-RetroArch" && nice -n 10 emmake make -f Makefile.core-objects objects -j2)
export SOURCE_DIR="$WORK/source" BUILD_DIR="$WORK/build-wasm" OUT_DIR="$WORK/out-network"
export EJS_RA="$WORK/EJS-RetroArch"
export GL_OVERRIDE="$PATCHES/gl_override-fixed.js"
nice -n 10 bash "$PATCHES/build-network.sh"
sha256sum "$OUT_DIR/flycast_libretro.js" "$OUT_DIR/flycast_libretro.wasm"
```

Patch application ignores line-ending whitespace because upstream audiostream.cpp has CRLF; a fresh-source reconstruction matched all38 patched/new files byte-for-byte against the tested source. Verify source pins and four rec-wasm hashes against pins.json before compilation; `python3 check-pins.py` checks every hash pinned for a file in this folder. build-network.sh compiles `flycast_stubs.c` from this folder. It replaces upstream's prebuilt `flycast_stubs.o`, whose source is absent upstream; the prebuilt object is no longer used. Recipe rebuilds from pinned inputs; artifact receipt hashes identify the tested build, not a guarantee of reproducible bytes across host/tool differences. Never promote a new hash automatically. Re-run export/ring, auth transport, actual guest DHCP, lifecycle and input qualification on produced bytes; user performs later two-device test.

Portable queue test: `bash test-queue.sh`. Actual production-service host test (JS/config/device edge shims): `bash test-service.sh`. Adapter tests: browser utility `npm test` plus `node --test core-patches/tests/reconnect.test.mjs`. Neither claims guest device delivery. Preserve complete compiler warnings and private receipts outside Git.

## VMU core revision

Apply the two VMU patches after the Ethernet patch. They add Emscripten-only
one-shot UTC configuration, actual RTC readback, stdio flush and a provisioned
mode that refuses `retro_unserialize`. Native/default behavior remains unchanged.
The new receipt in `pins.json` preserves prior Ethernet receipts separately.
This revision booted b8 with actual KOS UTC and completed authenticated local
utility input/Reset with durable VMU identity and fresh RNG.
