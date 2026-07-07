# Operator scripts (Linux workstation)

Three scripts, in the order you'd run them:

| Script | When | What it does |
|---|---|---|
| `setup.sh` | First clone, or after toolchain change | Verifies `cargo`, runs `fmt --check + clippy -D warnings + test + build --release`. Read-only against your account. |
| `configure-session.sh` | Once per session expiry | Interactively writes `$XDG_CONFIG_HOME/pdtui/session.json` from a bearer token + UID you paste in. Gitignored. Mode 0600. |
| `run-probes.sh` | After session configure, to validate live integration | Runs `pdtui probe` (Rust) and `node js-probe.mjs` (Tier-A JS) against your account; diffs status/ok side-by-side. |

## Capturing a session token (option B referenced in `configure-session.sh`)

Easiest sources, ordered by friction:

1. **Browser**: log into `drive.proton.me`, open devtools → Network → any `/api/drive/v2/...` request → Headers → grab `Authorization: Bearer <...>` and `x-pm-uid: <...>`.
2. **mitmproxy / Charles**: if you already proxy your browser traffic, the tokens are in the request headers tab.
3. **JS SDK CLI**: not currently in this checkout; see the commit log for `1491833 Add public CLI`, which lives in a separate Proton repo. If you have access, the CLI persists tokens to `auth-session.json` which you can `jq` for the values.

## Why two backends?

- **Rust backend** (`pdtui probe`): exercises `proton-drive-api` DTOs + `ReqwestHttpClient` retry middleware (M1 + M3). This is what we're building.
- **Node backend** (`js-probe.mjs`): raw `fetch` against the same endpoints with the same session. **No SDK dependency.** Acts as ground truth for the HTTP layer.

A divergence in `status` or `body_preview` between the two means the Rust side is sending a malformed request, missing a header, or mishandling a response. Same status + same body shape = M1 + M3 are correct.

For crypto-aware comparisons (decrypted folder listings, upload, download), we'd need **Tier B**, a Node shim that wraps the actual `@protontech/drive-sdk`. That's deferred until M2 crypto bodies land; see `HANDOFF.md` § "How to make progress."

## Safety notes

- `session.json` is mode 0600 and never logged.
- The token expires (~minutes to hours depending on Proton's session policy). When `probe` returns 401, re-run `configure-session.sh`.
- The HTTP middleware enforces `x-pm-appversion = external-drive-pdtui@…-stable`. Never edit that to spoof a first-party header.
- Three probes per run, all `GET`. No mutating operations.
