# Third-party notices: browser test tool

No game data, BIOS or credentials are included.

| Component | Used for | Licence | Text or source |
|---|---|---|---|
| Flycast | Emulator core, patched by `core-patches/` | GPL-2.0-or-later | `core-patches/LICENSE-GPL-2.0.txt`, pinned in `core-patches/pins.json` |
| flycast-wasm | WASM build foundation | GPL-2.0 | `core-patches/LICENSE-GPL-2.0.txt`, pinned in `core-patches/pins.json` |
| EmulatorJS RetroArch | Frontend linked into the core | GPL-3.0 | `core-patches/LICENSE-EJS-GPL-3.0.txt`, pinned in `core-patches/pins.json` |
| libslirp | Gateway helper's networking | BSD-3-Clause | Pinned in `gateway/dependencies.json` |

`core-patches/NOTICE.md` has the detail. `core-patches/flycast_stubs.c` replaces upstream's sourceless object, so every object linked into the core has its source here or at those pins.
