# inz-scan

**Detect — and if you choose, remove — the NullReceiver / “jsbot” npm supply-chain worm on developer machines.** macOS-first, Linux supported. No dependencies, no install step, single file.

Two identical implementations — **same detection set, same rails, same exit codes, verified to return byte-identical finding sets on the same fixture** ([`parity_check.js`](parity_check.js)):

```bash
node inz_scan.js scan                    # 1. Node — no preflight. Use this one.
python3 inz_scan.py scan                 # 2. Python — if python3 is already there
```

```bash
# either build, same flags
<runner> scan                    # read-only detection (default) — offline
<runner> remove-all --dry-run    # preview exactly what removal would do
<runner> remove-all --yes        # quarantine everything detected
```

**Prefer the Node build for handing to someone.** This campaign's victims are Node developers, so
`node` is already present — that removes the only real preflight the Python build has (`python3`,
which macOS does not ship). `inz_scan.js` alone is the complete tool.

No dependencies. No network. Never executes what it finds.

---

## If you arrived here because you saw one of these

You're in the right place. `inz-scan` was built from live samples of this campaign, not from a blog post.

`__inzRQ` · `__inzV=` · `.inz.cjs` · `.inz.orig` · `global.j=1` · `/*RS260605*/` · `/*C250617A*/` · `jsbot` · `~/node` · `~/py` · `x-payload-b64` · `Sec-V` · `0x/cls` · `/$/boot` · `9a47bb48b7b8ca41fc138fd3372e8cc0`

…or because you installed one of these npm packages:

`tailwindcss-motion-advanced` · `envpack-conf` · `postcss-initial-provider` · `agentgui` · `godot-kit` · `fluid-type-ui` · `bianira-ui` · `@kolbo/mcp`

See **[IOCS.md](IOCS.md)** for the full indicator set and **[TECHNIQUE.md](TECHNIQUE.md)** for how the chain works.

**Uninstalling the package is not enough.** This malware patches the npm CLI itself, so every later `npm install` re-runs it. Read [Order of operations](#order-of-operations-on-an-infected-mac) before you clean.

---

## Requirements — check this first

**Node 14.14 or newer — recommended, and there is nothing to install.** If you were hit through
npm, you have node, and that is the whole dependency list.

```bash
node --version           # want v14.14.0 or newer
node inz_scan.js scan    # no install, no build, no dependencies
```

**Python 3.8+ is supported as an alternative** (`inz_scan.py`), but it has a preflight the Node
build does not: on macOS `python3` is **not** part of the OS. `/usr/bin/python3` is an Xcode Command
Line Tools shim — if CLT is installed it works, and if it isn't it either pops an installer or fails
outright in a headless/SSH session. If you need that path:

```bash
python3 --version        # want 3.8 or newer
```

If it fails: `xcode-select --install` (a few GB) or `brew install python`.

> Tested with Node 18.19 and Python 3.12. The claim about macOS not shipping `python3` is *not*
> something we could verify — we have no Mac to test on. Run `python3 --version` and see for
> yourself before relying on that build.

---

## Handing this to someone else

The first step is always safe: `scan` is read-only and touches the network zero times, so it can be
run on a live, working machine without any preparation.

```bash
# 1. on their Mac - a read-only look. No install, no preflight.
node inz_scan.js scan --json before.json

# 2. have them send you before.json, and read it before touching anything
node inz_scan.js remove-all --dry-run          # still changes nothing
node inz_scan.js remove-all --yes              # quarantines, does not delete
```

Two things to get right when you hand it over:

- **Send the single file, not a whole archive, and give them the SHA-256** so they can confirm what
  they received is what you intended — see [`SHA256SUMS`](SHA256SUMS) for the authoritative values.
  (`shasum -a 256 inz_scan.js` on macOS.) They can also read the whole thing first: plain source,
  no minification, no bundled data, no dependencies.
- **Treat `before.json` as sensitive.** It records hostnames, usernames and file paths from their
  machine. It is not a public artefact.

They do **not** need the rest of this repo to run a scan — `inz_scan.js` alone is complete.

---

## What it finds

**The packages** — all eight names above, with the version read from `package.json`.

**Injection markers** the worm stamps into every file it touches — `/*RS260605*/`, `/*C250617A*/` … `/*M260630A*/`.

**Content signatures** — the `global.i='<tag>';global.j=1` loader prologue, the `__inzCR` / `__inzV=` / `__inzRQ` ESM+CJS injection shims, `.inz.cjs` references, `x-payload-b64`, the dead-drop wallet, C2 paths, RAT command names (`ss_eval64`, `ss_upf`, `ss_fcd`), and the anti-analysis digest `9a47bb48b7b8ca41fc138fd3372e8cc0`.

**Injection targets**, checked explicitly — the **npm CLI** in every global root (`npm root -g`, nvm, Homebrew), **VS Code / Cursor / Antigravity** (`out/main.js` + `@vscode/deviceid/dist/index.js`), **Discord Desktop** (`discord_desktop_core/index.js`), **GitHub Desktop** — `/Applications/...` paths first on macOS.

**Artefacts** — `.inz.cjs` / `.inz.orig` / `.inz.tmp`, `.npm-install.lock`, the campaign's install roots `~/node` `~/py` `~/node20`, `nm-npm-cache-*` in `/tmp`.

**Historical exposure** — the npm cache index and every `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` under your home. This proves a package was pulled **even after `node_modules` has been cleaned**.

**Live compromise** — the process table, the local socket table against the three known C2 addresses, `NODE_OPTIONS` / `_VSCODE_PRODUCT_JSON`, `~/.zshrc` / `~/.zprofile` / `~/Library/LaunchAgents/*.plist`.

---

## Safety rails

Running an unknown binary on a machine you suspect is compromised is a bad idea. This one is built for that situation.

| Guarantee | How |
|---|---|
| **Offline** | zero network calls. It never resolves or contacts the C2 — a scanner that phones home tips off the operator and re-discloses your IP. |
| **Never executes anything** | text scanning only. It never `require`s, imports, evaluates or spawns any file it finds. |
| **`scan` cannot write** | the only writer is `--json`, to the path you name. |
| **Quarantine, not delete** | `remove-all` *moves* artefacts into `~/inz-quarantine-<ts>/` and keeps the infected copy of anything it restores. `--purge` is opt-in. |
| **Refuses to guess** | no file is touched unless it matches a known signature. |
| **Self-verifying** | after stripping a file it re-runs `node --check` if node is present, and reports residual-risk markers. |

---

## Usage

```bash
node inz_scan.js scan                        # read-only detection
node inz_scan.js scan --deep                 # also open every JS/TS file, not just the allowlist
node inz_scan.js scan --json report.json
node inz_scan.js scan --root /Users/them     # limit scope (repeatable)
node inz_scan.js scan --exclude ~/samples    # skip a dir (e.g. your own evidence folder)

node inz_scan.js remove-all --dry-run        # preview, changes nothing
node inz_scan.js remove-all --yes            # quarantine
node inz_scan.js remove-all --yes --strip    # also neutralise injected code blocks
node inz_scan.js remove-all --yes --purge    # delete after backing up
```

`inz_scan.py` takes **identical flags and exit codes** — swap `node inz_scan.js` for
`python3 inz_scan.py`. `<runner> --help` on either.

Exit codes: `1` findings (CI-friendly), `0` clean, `2` you forgot `--yes`.

`--exclude` matters if you keep malware samples or IOC files on the disk: they legitimately contain every marker this tool looks for. Anything under an `inz-quarantine-*/` directory it created is skipped automatically.

---

## What removal does — and its honest limits

1. **Files with the worm's own `.inz.orig` backup** → restored byte-exact, and only if that backup is itself verifiably clean. The worm helpfully keeps the original; this is the cleanest fix available. The infected copy is retained in quarantine as evidence.
2. **Unambiguous artefacts** (`.inz.cjs`, `~/node`, `~/py`, `nm-npm-cache-*`, package dirs) → quarantined.
3. **Injected application files with no usable backup** → **it does not patch them.** It prints the reinstall command instead (`npm i -g npm@latest`, reinstall VS Code, …). Patching a vendor binary it cannot verify is worse than reinstalling it.
4. **`--strip`** (opt-in) neutralises injected blocks using the **worm's own removal regexes**, recovered from its string table. It preserves line structure, re-runs `node --check`, and flags residual risk.
5. **npm cache and lockfiles** → reported, never auto-edited, with the exact follow-up.

### The safety case that matters

`--strip` will **not** truncate a file to end-of-file unless what follows the injected prologue looks like the minified loader itself. If legitimate code follows the injection it leaves it alone and prints `[appended loader prologue found but code follows it - NOT truncated, review manually]`. This was a real data-loss bug caught by the test suite.

---

## Verify it before you trust it

```bash
node selftest_inz_scan.js        # 32 checks - Node build
python3 selftest_inz_scan.py     # 33 checks - Python build
node parity_check.js             # do both builds report the same findings?
```

Current state: **Node 32/32, Python 33/33, and parity check reports identical finding sets.** Verification actually performed:

| Check | Result |
|---|---|
| Node regression suite | 32/32 pass |
| Python regression suite | 33/33 pass |
| Cross-implementation parity (same fixture, env-independent findings) | **13/13 identical** |
| Whole home tree (excluding the malware-evidence folder) | **NO INDICATORS FOUND** |
| `/home/ubuntu/tools`, `pentest/training`, `/usr/local/lib/node_modules` | 0 findings |
| Pointed at the real retrieved payloads | 17 findings, 16 critical (correct detection) |
| Benign control using `global.i='v1'; global.j=2;` and a `0xe1f0` hex constant | not flagged |

### Platform status — read this

The tool is **macOS-first by design** (`/Applications/*.app` targets, `~/Library/Application Support/discord`, `~/Library/LaunchAgents`, `lsof`), but it was **developed and validated on Linux**. CI runs the full suite on `macos-latest` and `ubuntu-latest` on every push, which proves it runs and passes there — it does **not** prove behaviour against a real infected Mac, because we don't have one to test on. Treat the first macOS run as a detection pass and read its output before using `remove-all`.

## Known limits

- Signature-based against this family as recovered on **2026-10-05**. A rebuilt variant with new markers needs new signatures.
- It cannot see inside an encrypted volume it lacks access to, or detect a dormant infection it has no signature for.
- `--deep` on a very large home directory takes a while; the default scan trades completeness inside `node_modules` for speed.
- **The process check matches on full command-line arguments**, so any process whose argv merely *mentions* a marker is reported — an analyst running `grep -r .inz.cjs`, or a shell sourcing a script with those strings in it. Treat a `process` finding as something to eyeball, not as proof of a live infection on its own. The high-signal case is a detached `node -e` whose argv carries `global['_V']`.
- `lsof` without root only sees your own sockets. The malware runs as you, so that is usually enough — but it will not attribute connections to other users' processes.
- It is not a substitute for reinstalling the OS if the machine held high-value secrets.

---

## Order of operations on an infected Mac

1. **Isolate from the network.** The worm re-infects on every editor launch and every `npm install` — cleaning while online undoes itself.
2. `inz_scan.py scan --json before.json` — capture the state.
3. `inz_scan.py remove-all --dry-run` — read the plan.
4. `inz_scan.py remove-all --yes` — execute it.
5. **Reinstall** whatever it listed, then quit every editor.
6. `npm cache clean --force`, then fix the lockfiles it flagged.
7. `inz_scan.py scan` — confirm clean.
8. **Rotate credentials regardless of the scan result:** npm tokens (`~/.npmrc`), GitHub PAT/SSH, cloud instance roles, SSH keys, browser passwords, Discord tokens, and **any crypto wallet seed phrase that ever crossed that clipboard** — clipboard theft is a first-class feature of this malware.
9. Tell whoever owns the packages and repos that machine published to, and check the CI runners that built them.

---

## Related

- **[IOCS.md](IOCS.md)** — full indicator set (markers, C2, endpoints, keys, install roots)
- **[TECHNIQUE.md](TECHNIQUE.md)** — how the chain works and how it was unpacked
- **[rules/](rules/)** — YARA rules for the stage-1 loader

## License

MIT — see [LICENSE](LICENSE).
