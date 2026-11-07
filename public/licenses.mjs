// SPDX-License-Identifier: MIT
// Link the source to the exact tag or commit of the public repository this site was deployed from, when stamp-source.py recorded one.
const repository = "https://github.com/lamb2k/dce-web-tool";
try {
  const response = await fetch("/source.json", { cache: "no-store" });
  const value = response.ok ? await response.json() : null;
  if (value && /^[0-9A-Za-z._-]{1,64}$/.test(value.ref)) {
    document.getElementById("source").href = `${repository}/tree/${value.ref}`;
    document.getElementById("notices").href = `${repository}/blob/${value.ref}/NOTICES.md`;
    document.getElementById("commit").textContent = `at ${value.ref.slice(0, 16)}`;
  }
} catch { /* the static links stay */ }
