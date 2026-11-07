// Private files stay outside Git. VMU/UTC core, qualified with actual b8 KOS RTC.
export const CORE = Object.freeze({
  javascript: { path: "/files/flycast_libretro-vmu.js", bytes: 310208, sha256: "ac74880076412d78907546354005c0395a2d53545037868a245146f7285b9b73" },
  wasm: { path: "/files/flycast_libretro-vmu.wasm", bytes: 10446310, sha256: "948835c97eafb4d4f1f1eba69c56c6007524ae091eb39b0cb97d8fafbdc5c4b9" },
});
export const AUDIO_LATENCY_MS = 64;
const keyButtons = { Enter: 3, ArrowUp: 4, ArrowDown: 5, ArrowLeft: 6, ArrowRight: 7,
  Space: 0, KeyZ: 0, KeyX: 8, KeyC: 1, KeyV: 9, KeyQ: 12, KeyE: 13 };
const padButtons = [0, 8, 1, 9, 12, 13, 12, 13, 2, 3, 14, 15, 4, 5, 6, 7];
const clamp = value => Number.isFinite(value) ? Math.max(-1, Math.min(1, value)) : 0;
export function inputValues({ keys = [], buttons = [], axes = [] } = {}) {
  const values = new Int32Array(24);
  for (const key of keys) if (keyButtons[key] !== undefined) values[keyButtons[key]] = 1;
  buttons.slice(0, 16).forEach((value, i) => { if (value > 0.5) values[padButtons[i]] = 1; });
  const held = new Set(keys);
  const x = clamp((held.has("KeyD") ? 1 : 0) - (held.has("KeyA") ? 1 : 0) + (axes[0] ?? 0));
  const y = clamp((held.has("KeyS") ? 1 : 0) - (held.has("KeyW") ? 1 : 0) + (axes[1] ?? 0));
  [x, y, clamp(axes[2] ?? 0), clamp(axes[3] ?? 0)].forEach((value, i) => {
    if (Math.abs(value) >= 0.15) values[16 + i * 2 + (value < 0 ? 1 : 0)] = Math.round(Math.abs(value) * 32767);
  });
  return values;
}
