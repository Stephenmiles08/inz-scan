# Changelog

## 1.2 — 2026-10-05

Portability fix and hand-off documentation.

- `scan_processes()` now invokes `ps -Ao pid=,args=` instead of `ps -eo pid=,args=`.
  On Linux `-e` means “every process”; on the BSDs/macOS `-A` is the unambiguous spelling.
  `-A` is correct on both, so there was no reason to rely on `-e`.
- README: added a **Requirements** section (Python 3.8+, plus the macOS `python3` /
  Xcode Command Line Tools preflight) and a **Handing this to someone else** section
  covering the SHA-256 check and the fact that `before.json` records machine identifiers.
- Added `SHA256SUMS`.

## 1.1 — 2026-10-05

Initial public release.

- `scan` — read-only, offline detection of the NullReceiver / "jsbot" developer worm
- `remove-all` — opt-in quarantine with `--dry-run`, `--strip`, `--purge`, `--backup-dir`
- Detects 8 malicious npm packages, 7 injection markers, the `global.i / global.j=1` loader
  prologue, the `__inzCR` / `__inzV=` / `__inzRQ` injection shims, `.inz.*` staging artefacts,
  the campaign install roots (`~/node`, `~/py`, `~/node20`), `nm-npm-cache-*`, the npm CLI in
  every global root, VS Code / Cursor / Antigravity / Discord / GitHub Desktop injection sites,
  npm cache and lockfile exposure, live processes, C2 sockets, environment variables and
  launchd / shell-rc persistence
- Restores injected files byte-exact from the worm's own `.inz.orig`, only when that backup is
  itself verifiably clean
- Refuses to patch vendor binaries it cannot verify — prints the reinstall command instead
- `--strip` reuses the worm's own removal regexes, preserves line structure, and re-runs
  `node --check` on the rewritten file
- `selftest_inz_scan.py` — 33 checks covering detection, removal, strip safety and option handling
- CI matrix on ubuntu-latest + macos-latest, including a static check that no HTTP client is imported

### Bugs found and fixed during development, via the test suite

- **Data loss:** `--strip` truncated to end-of-file when it saw an appended loader prologue,
  destroying legitimate code that followed the injection. Now guarded — it only truncates when
  the tail looks like the minified loader (no line comments, no blank lines), and otherwise reports
  `code follows it - NOT truncated, review manually`.
- **Missed the payload:** the content grep tested `dirpath.name == "node_modules"`, which skips
  `<pkg>/npm/lib/` — exactly where the worm's own engine lives. Now tests
  `"node_modules" in Path(dirpath).parts`.
- **Removal failed on directories:** `shutil.copy2` cannot copy a directory
  (`[Errno 21] Is a directory`). Now uses `shutil.move` (quarantine) or `copytree` + `rmtree` (purge).
- A loader beginning at byte 0 was not matched by a pattern requiring a preceding newline.
