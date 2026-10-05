# How the chain works

Reconstructed from live samples on **2026-10-05**. Everything below was derived statically —
no payload was executed.

## Attribution

The loader is the **NullReceiver** technique used by the DPRK-linked **Contagious Interview**
campaign (Lazarus lineage), delivered through npm. The hard-coded dead-drop wallet
`0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a` is the same wallet named in public reporting
(Sonatype 2026-08-10, GHSA-44q9-v3f9-xcx6, The Hacker News 2026-08-05, OpenSourceMalware).

## Stage 1 — the loader (1 line, 25 KB)

Obfuscated with javascript-obfuscator: a rotated hex string-array XOR'd with a single byte
(`0xa2`), reached through 30 aliases of one decoder. Unpacked: 215/215 call sites resolved.

It resolves its C2 **from the blockchain** rather than from a domain:

1. Reads the latest Ethereum block, then finds an outbound transaction from the dead-drop wallet.
   Three independent recovery paths (6-block neighbourhood probe, nonce binary search, Blockscout
   indexer), four raced JSON-RPC providers, batched calls, `ETH_RPC_URL` override.
2. Decodes the C2 IP **out of the `to` field**: bytes 0–3 and 4–7 are two IPv4 addresses,
   bytes 8–19 are a static marker (`helloipbot!!`). A 20-byte address carries 8 bytes of config.
3. Fetches two stages over **plain HTTP on tcp/443** — no TLS, deliberately: it blends with
   “https to port 443” in naive egress logs.

That design is the point: **there is no domain and no certificate to seize.** Re-targeting is one
transaction, and the operator re-posts on a fixed cadence (every 1000 blocks, always at
`block % 1000 == 999`).

## Stage 2 — the worm + RAT (123 KB, delivered as `/0x/clb`)

Not a dropper — a **self-propagating worm with a full remote-access trojan attached**. Recovered
string table: 487 entries, which is where the whole capability map came from.

**It is persistent by patching other software.** The worm writes itself into:

- **npm's own CLI** (`node_modules/npm/lib/cli.js`, located via `npm root -g`) — so it re-executes on
  **every `npm install`**
- **VS Code, Cursor, Antigravity** (`out/main.js` and `@vscode/deviceid/dist/index.js`) — so it
  re-executes on **every editor launch**
- **Discord Desktop** and **GitHub Desktop**

Windows, macOS and Linux paths are all covered, plus WSL detection. It fingerprints for CI
(`github-runner`, `buildbot`, `sandbox-pool-`, `buildkitsandbox`, `cloudchamber`) before deciding
how to behave.

**RAT:** a socket.io client it installs on demand (`socket.io-client@4.7.5` into a scratch npm
prefix, so it is never a visible dependency), with clipboard theft (`pbpaste`, `powershell
Get-Clipboard`, `xclip`, `xsel`), multipart file upload, remote eval, host recon, and a Python
second stage delivered through `python3 -c` into `~/py`.

**Evasion and anti-forensics:** an MD5 process-name blocklist, marker comments so injected files can
be found *and excised*, ESM↔CJS rewriting (`createRequire as __inzCR`) after stripping `'use strict'`,
and `.inz.orig` backups that let it also **un-infect** a host. That backup is what `inz-scan`
restores from.

## Stage 3 — `/$/boot`, the gatekeeper (64 KB)

This is the piece that decides **whether a host is worth infecting at all**, then installs the
persistent Python backdoor.

It refuses to run on **67 hostname/username patterns** — CI runners, containers, cloud sandboxes,
devcontainers — plus `^[0-9a-f]{12}$` (container ID) and UUID-shaped names, and fingerprints the
runtime (`K_SERVICE`, `NEXT_DEPLOYMENT_ID`, `VERCEL_HIVE_VERSION`, `pm_uptime`, `vizion_runni`).

**That has a direct consequence for responders:** an analysis VM or build runner showing nothing may
be a *declined* infection rather than a clean host. Do not read a quiet CI box as proof of safety.

macOS is a first-class target (`darwin`, the `Mac-` hostname prefix, `.lan`, `192.168.` are handled in
the same decision tree), which is consistent with landing on a developer's Mac and not the build box.

After qualifying a host it installs `axios` + `socket.io-client`, unpacks a bundled Python
(`tar`, or a dropped `/d/7zr.exe` on Windows), and runs the backdoor. It still carries `/0x/cls` and
its key — **the chain is circular, not linear.**

## How these were unpacked

Recorded because the same shapes recur:

1. **String-array + XOR** (§stage 1): extract the array function and decoder textually, run *only*
   those in a `node:vm` context with `require()` stubbed to throw, then substitute call sites.
   Find every alias first — one decoder had 30.
2. **`Function()` wrapper + LZ-string table** (§stage 2): the payload carries its own lz-string
   decompressor. Extract the library and the blob literal (strictly validated as a bare string
   literal before evaluation), decompress, and the 487-entry string table falls out.
3. **Per-call RC4 decoder** (§stage 3): `_0xd(idx, key)` = array lookup → custom base64 → RC4.
   Two traps cost real time and are worth stating:
   - **The declared rotation loop cannot bootstrap itself.** Its convergence test sums
     `parseInt(decoded)` against a target, but before the array is rotated the decoder returns
     binary garbage — every term is `NaN`, so it spins forever. It presents as a VM *timeout*.
     Solve the offset by scanning (it was **148**), then clear the decoder's memo cache.
   - **Substitute the original call text, not the evaluated form.** The file contains
     `aW(']]tt',a0fC.a)`; nothing matches `aW(']]tt',0x6fd)`. Getting this backwards looks like a
     partial decode (210/851 sites) rather than a bug in your tooling.
4. **Concatenation-merge before keyword hunting.** Literals are chunked (`"npm --prefix"+"\\x20\\x22"`),
   so the C2 key, the npm command and the anti-analysis digest are all invisible until you collapse
   `"…"+"…"` runs.

## What was *not* done

- No payload was executed at any point. The only code that ran was the malware's **own** decoders,
  inside a sandbox with `require` stubbed out.
- The C2 was contacted only to **retrieve** stages, from a recorded egress IP, with no POSTs, no
  beacon and no execution of anything returned. Future C2 interaction should go through a
  throwaway host.
- Stage-2 payloads are **not redistributed** in this repository.
