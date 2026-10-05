# Indicators of Compromise

Family: **NullReceiver** blockchain dead-drop loader → **“jsbot” developer worm + RAT**
Attribution: DPRK **Contagious Interview** / Lazarus lineage
Indicators recovered: **2026-10-05** from live samples

> **This file contains indicators only — no malware bytes and no live payloads.** The
> detector and the IOCs are here so defenders can confirm and clean. The second-stage
> payloads are deliberately not redistributed.

---

## Markers the worm stamps into files it injects

```
/*RS260605*/   /*C250617A*/   /*C250618A*/   /*C250619A*/
/*C250620A*/   /*C260511A*/   /*M260630A*/
```

Injected file signature:

```js
global.i='<tag>';global.j=1;global['e']='<b64>'
```

`global.j=1` is the reliable “this file is already infected” marker. Observed build tags:
`A11--#` (stage 1), `A4` (stage-2 default). Internal version `260902`.

Injection shims, ESM and CJS variants:

```js
import{createRequire as __inzCR}from'module';const __inzV='<ver>';__inzCR(import.meta.url)('<path>.inz.cjs')
const __inzV='<ver>';const __inzRQ=require('<path>.inz.cjs')
```

## Staging artefacts

`.inz.cjs` · `.inz.orig` · `.inz.tmp` · `.npm-install.lock` · `nm-npm-cache-*`

`.inz.orig` is the worm's own backup of the pre-infection file — **that is what `remove-all` restores from.**

## Malicious npm packages

| Package | Note |
|---|---|
| `tailwindcss-motion-advanced@1.0.1` | loader inside `utils.min.js` |
| `envpack-conf@1.0.1` | published malicious |
| `postcss-initial-provider@3.0.4` | published malicious |
| `agentgui@1.0.1127` | hijacked (loader appended to `database.js`) |
| `godot-kit@1.0.1786316795` | hijacked |
| `@kolbo/mcp@1.57.1` | hijacked |
| `fluid-type-ui@2.0.8` | prior NullReceiver sample |
| `bianira-ui` | prior NullReceiver sample |

## Blockchain dead drop

- **Wallet:** `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a`
- **Mechanism:** bytes 0–3 of `tx.to` = C2 IP #1, bytes 4–7 = C2 IP #2, bytes 8–19 = static ASCII marker `helloipbot!!`
- **Cadence:** one tx per 1000 blocks (~3h20m), at `block % 1000 == 999`

## C2 infrastructure

| IP | Active window | Network |
|---|---|---|
| **`91.218.183.174`** | 2026-09-28 → present | Evoxt Enterprise (GB) |
| `166.88.134.75` | 2026-09-17 → 2026-09-28 | Evoxt (UK) |
| `193.247.144.38` | 2026-09-09 → 2026-09-17 | Evoxt Enterprise (GB) |

All traffic is **plain HTTP**, frequently to `tcp/443` with no TLS.

## Endpoints and payload keys

| Path | Port | Key (repeating-key XOR) | Role |
|---|---|---|---|
| `/0x/cls` | 443 | `q4FZkxX{!h,Sr3=@` | client-loader → `eval` in-process |
| `/0x/ls` | 443 | `y-p_>d$0B&@^1aQk` | fetches `/$/boot`, `eval`s it |
| `/0x/clb` | 443 | `q4FZkxX{!h,Sr3=@` | JSON `{inz, body:base64(XOR)}` → **the worm** |
| `/0x/cb` | 443 | `q4FZkxX{!h,Sr3=@` | same bytes, raw XOR channel |
| `/0x/js` | 443 | *(plaintext)* | 1.5 MB flattened-VM copy of the worm (`inz`) |
| `/$/boot` | **80** | `ThZG+0jfXE6VAGOJ` | target qualification + Python backdoor installer |
| `/verify-human/<tag>` | 80 | *(plaintext)* | beacon, disguised as a CAPTCHA check |

`x-payload-b64` response header = base64 of the same body (redundant channel, verified).
All requests carry `Sec-V: <tag>` and a Chrome-131 user-agent.

### Worm payload hashes (for matching, not for distribution)

- `/0x/clb` and `/0x/cb` (XOR-decrypted): `41cb56f3b8e2df7c61b671813317aa277f59bbfb374cfddd483d22eec44723ff`
- `/$/boot` (XOR-decrypted): `ab8a54f50bbda7eb2156941ef99a801158794a787bd9d78bbe6cf6822e53fd1a`

## Injection targets

- `npm/lib/cli.js` in every global npm root — **the worm's propagation engine**
- VS Code / Cursor / Antigravity — `…/app/out/main.js` and `…/node_modules/@vscode/deviceid/dist/index.js`
- Discord Desktop — `modules/discord_desktop_core/index.js`
- GitHub Desktop — `…/app/main.js`

## Install roots and RAT artefacts

`~/node` · `~/py` · `~/node20` · `~node` · `~py`

The RAT installs `socket.io-client@4.7.5` on demand into a temp prefix (`nm-npm-cache-*`) so it is
never a visible dependency. Operator commands: `ss_info`, `ss_ip`, `ss_cb`, `ss_upf`, `ss_upd`,
`ss_dir`, `ss_fcd`, `ss_stop`, `ss_inz:`, `ss_inzx:`, `ss_connect:`, `ss_eval:`, `ss_eval64:`,
`ss_exit`, `ss_exit_f`. Second-stage Python delivered via `python3 -c`.

## Evasion

- Anti-analysis process-name digest: `9a47bb48b7b8ca41fc138fd3372e8cc0` → prints `Blocked by security` and refuses to run
- `tasklist /FO CSV /NH` (Windows), `NODE_OPTIONS`, `_VSCODE_PRODUCT_JSON`
- Hooks: `code/willLoadMain`, `code/didStartMain`, `bootstrapESM`, `SandboxManager`, `sandbox-config`
- `/ $/boot` refuses to infect CI, container and cloud-sandbox hosts — 67 hostname/username gates
  (`github-runne`, `buildbot`, `sandbox-pool`, `buildkitsandbox`, `cloudchamber`, `devcontainer`,
  `codespace`, `ip-172-`, `100.64.`, `ssm-user`, `runnervm`, …) plus `^[0-9a-f]{12}$` (container ID)
  and UUID patterns. Cloud fingerprints: `K_SERVICE`, `NEXT_DEPLOYMENT_ID`, `VERCEL_HIVE_VERSION`,
  `pm_uptime`, `vizion_runni`.
- **Consequence:** a CI or analysis VM showing nothing may be a *declined* infection, not a clean host.

## Network detection

- Plain HTTP to a **bare IP on tcp/443** — near-zero false positives
- Any request carrying a `Sec-V:` header, or a response with `x-payload-b64`
- Paths `/0x/cls`, `/0x/ls`, `/0x/clb`, `/0x/cb`, `/0x/js`, `/$/boot`, `/verify-human/`

## YARA

[`rules/nullreceiver_loader.yar`](rules/nullreceiver_loader.yar) — two rules (shipped-artefact
markers + decoded-form indicators). Note the shipped loader XORs its strings, so a rule keyed only
on the plaintext IOCs above will **miss the file as shipped**; both rule shapes are included.

## Reporting

C2 addresses → Evoxt abuse. Packages and infrastructure → the OSSF malicious-packages tracker and
the relevant GHSA advisories.
