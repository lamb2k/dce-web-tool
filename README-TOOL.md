# Browser test utility

One page, shared tester login, automatic pinned image preparation, Play/Reset, keyboard and gamepad controls and diagnostic download. No account database, lobby or chat.

## Local checks

Node 22+: `npm test`. No runtime dependencies or install needed.

Optional workerd/R2 check: set `MINIFLARE_MODULE` to an installed Miniflare entry-point file URL, then `node tests/runtime-smoke.mjs`. It uses synthetic bytes.

Gateway: see `gateway/README.md`. Core: see `core-patches/README.md`.

## Configure and run

Copy `wrangler.example.jsonc` to `wrangler.jsonc` and fill in the Worker name, hostname and bucket. The bucket must stay private: no public object URLs.

Local preview needs an ignored `.dev.vars` with `TEST_USERNAME` (1-64 letters, digits, underscore, dash) and `TEST_PASSWORD` (16-256 printable ASCII). There are no default credentials. Use Wrangler secrets in a deployment.

Packaging check: `npx wrangler@4.131.1 deploy --dry-run --config wrangler.jsonc --outdir .wrangler/qualification`.

Deploy: `npx wrangler@4.131.1 deploy --config wrangler.jsonc`. The example sets `PUBLIC_ACCESS` to `0`, which asks for the password. Add `--var PUBLIC_ACCESS:1` on every deploy of a public site: Wrangler replaces plain variables each time.

With `PUBLIC_ACCESS=1` the page needs no password and hands each browser a session. New sessions are limited to 20 a minute per IPv4 address or IPv6 /64, and failed sign-ins to 10 a minute. `/files/*` still needs a session.

Before each deploy, `python stamp-source.py <tag or commit>` records what the "Source and licences" page links to.

## The image

The tool runs an image you supply. Upload a `build.json` and your image to the private bucket:

```json
{
  "schema": 1,
  "status": "ready",
  "build": "<alphanumeric-dot-underscore-dash-label>",
  "commit": "<40-lowercase-hex-source-commit>",
  "image": {
    "path": "/files/<image>.cdi",
    "bytes": 1,
    "sha256": "<64-lowercase-hex-image-hash>"
  }
}
```

The example holds placeholders. The image limit is 128 MiB. The page checks size and SHA-256 before passing bytes to the runtime, and caches one verified image in IndexedDB. Image paths take a single basename: traversal, nested paths and URL syntax are refused.

`public/runtime-config.mjs` pins the core's JS and WASM. Host your own build of the core: it is not in this repository.
