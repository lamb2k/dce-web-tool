# Source notices

No emulator binaries, BIOS, game assets, credentials or private endpoints included.

- Flycast source: flyinghead and upstream contributors. Headers retain GNU GPL version2 or later; license text in LICENSE-GPL-2.0.txt. Baseline patch preserves original notices.
- WASM/DRC foundation and build script: nasomers/flycast-wasm, pinned in pins.json; upstream repository includes GPL version2 text. Four rec-wasm source files fetched from that pinned source, with original contents/notices retained.
- EJS RetroArch frontend: EmulatorJS/RetroArch contributors; separate pinned source carries GPL version3, copied here as LICENSE-EJS-GPL-3.0.txt. No frontend object or binary included.
- New BrowserEthernetService, bounded queue, adapter and tests: GNU GPL version2 or later. Original upstream notices must remain when applying patches. `public/browser-ethernet.mjs` is the production copy of the adapter under the same terms.
- `LICENSE` in this folder is the GPL version2 text and governs this folder, whatever the repository root says. The repository's MIT licence does not apply to these files.

build-network.sh adapts upstream build-prod.sh: bounded parallelism, isolated cache requirement, corrected archive member stripping, and libzip/miniupnpc/libelf closure. gl_override-fixed.js retains the existing SDK extension-enumeration correction. These are source/build inputs, not a claim that third-party core issues are resolved.
- `flycast_stubs.c`: GNU GPL version2 or later, written here to replace upstream's sourceless `flycast_stubs.o`. Same five symbols and behaviour.
- `public/browser-ethernet.mjs`: the production copy of `adapter/browser-ethernet.mjs`, GNU GPL version2 or later, outside this folder. It carries its own SPDX line.
