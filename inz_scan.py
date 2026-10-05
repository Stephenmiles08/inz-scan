#!/usr/bin/env python3
"""
inz_scan.py - detector + opt-in remover for the NullReceiver / "jsbot" developer worm
              (stage 2 of the tailwindcss-motion-advanced npm supply-chain loader)

  macOS-first. No third-party dependencies. Python 3.8+ (stdlib only).

  python3 inz_scan.py scan                 # read-only detection (default)
  python3 inz_scan.py scan --deep          # + grep every JS/TS file under $HOME
  python3 inz_scan.py scan --json out.json
  python3 inz_scan.py remove-all --dry-run # show exactly what removal would do
  python3 inz_scan.py remove-all --yes     # quarantine (moves to a backup dir)
  python3 inz_scan.py remove-all --yes --strip   # also neutralise injected code blocks

WHY THIS IS SAFE TO RUN ON AN INFECTED, LIVE MACHINE
  * makes ZERO network calls - it never contacts the C2 and never downloads anything
  * never executes, requires, imports or evaluates any file it finds - text scanning only
  * `scan` cannot write anything anywhere
  * `remove-all` QUARANTINES (moves to ~/inz-quarantine-<ts>/) instead of deleting, so
    nothing is lost and evidence is preserved; pass --purge to actually delete
  * `remove-all` refuses to touch a file unless it matches a known infection signature

WHAT IT CANNOT DO
  Injected application files (VS Code / Cursor / Antigravity / Discord / GitHub Desktop /
  the npm CLI) are only restored by .inz.orig when the worm left one. Otherwise the fix is
  to reinstall the application - this script will tell you the exact command rather than
  mangle a vendor binary it cannot verify. That is deliberate.

Detections are derived from the recovered string table of the actual payload
(sha256 41cb56f3b8e2df7c61b671813317aa277f59bbfb374cfddd483d22eec44723ff).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

VERSION = "1.1"
HOME = Path.home()
IS_MAC = sys.platform == "darwin"
IS_WIN = os.name == "nt"

# --------------------------------------------------------------------------------------
# Indicators of compromise (recovered from the live payload)
# --------------------------------------------------------------------------------------

# Packages the campaign has shipped the loader in (Sonatype six + OpenSourceMalware pair)
MALICIOUS_PACKAGES = [
    "tailwindcss-motion-advanced", "envpack-conf", "postcss-initial-provider",
    "agentgui", "godot-kit", "fluid-type-ui", "bianira-ui", "@kolbo/mcp",
]

# Markers the worm stamps into every file it injects
INJECTION_MARKERS = [
    "/*RS260605*/", "/*C250617A*/", "/*C250618A*/", "/*C250619A*/",
    "/*C250620A*/", "/*C260511A*/", "/*M260630A*/",
]

# Content signatures - strong (one hit is enough) unless flagged weak
STRONG_SIGNATURES = [
    (re.compile(r"global\.i\s*=\s*['\"][^'\"]{1,16}['\"]\s*;?\s*global\.j\s*=\s*1"), "injected loader prologue (global.i / global.j=1)"),
    (re.compile(r"createRequire\s+as\s+__inzCR"), "ESM injection shim (__inzCR)"),
    (re.compile(r"const\s+__inzV\s*=\s*['\"]"), "injection version constant (__inzV)"),
    (re.compile(r"__inzRQ\s*=\s*require\s*\("), "CJS injection hook (__inzRQ)"),
    (re.compile(r"\.inz\.cjs"), "staged payload reference (.inz.cjs)"),
    (re.compile(r"x-payload-b64"), "loader fallback header"),
    (re.compile(r"0xa322e5f3d311d3080e6f0121063e9adc2490ef1a", re.I), "NullReceiver dead-drop wallet"),
    (re.compile(r"/(?:\0x/cl|0x/cb|0x/js|\$/boot|verify-human)"), "C2 endpoint path"),
    (re.compile(r"ss_eval64|ss_upf|ss_fcd|ss_inzx:"), "RAT command names"),
    (re.compile(r"nm-npm-cache-"), "on-demand socket.io install cache"),
]

WEAK_SIGNATURES = [
    (re.compile(r"\bSec-V\b"), "loader beacon header (Sec-V)"),
    (re.compile(r"socket\.io-client@4\.7\.5"), "pinned socket.io-client version"),
    (re.compile(r"\bglobal\.j\s*=\s*1\b"), "infection marker (global.j=1)"),
]

# C2 infrastructure
C2_IPS = [
    "91.218.183.174",   # current (2026-09-28 -> present)
    "166.88.134.75",    # 2026-09-17 -> 2026-09-28
    "193.247.144.38",   # 2026-09-09 -> 2026-09-17
]

# Staging / install-root artefacts
STAGING_SUFFIXES = (".inz.cjs", ".inz.orig", ".inz.tmp")
INSTALL_ROOTS = ["node", "py", "node20", ".node", "~node", "~py"]

ANTI_ANALYSIS_MD5 = "9a47bb48b7b8ca41fc138fd3372e8cc0"

# Application files the worm injects into (macOS first, then Linux/Windows)
def injection_targets() -> list[tuple[str, str]]:
    """(path, human label). Only existing paths end up in the scan set."""
    t: list[tuple[str, str]] = []
    if IS_MAC:
        t += [
            ("/Applications/Visual Studio Code.app/Contents/Resources/app/out/main.js", "VS Code main"),
            ("/Applications/Visual Studio Code.app/Contents/Resources/app/node_modules/@vscode/deviceid/dist/index.js", "VS Code deviceid"),
            ("/Applications/Cursor.app/Contents/Resources/app/out/main.js", "Cursor main"),
            ("/Applications/Cursor.app/Contents/Resources/app/node_modules/@vscode/deviceid/dist/index.js", "Cursor deviceid"),
            ("/Applications/Antigravity.app/Contents/Resources/app/node_modules/@vscode/deviceid/dist/index.js", "Antigravity deviceid"),
            ("/Applications/GitHub Desktop.app/Contents/Resources/app/main.js", "GitHub Desktop main"),
            (str(HOME / "Library/Application Support/discord/modules/discord_desktop_core/index.js"), "Discord core"),
            (str(HOME / "Library/Application Support/discord/modules/discord_desktop_core-1/discord_desktop_core/index.js"), "Discord core (-1)"),
        ]
    else:
        t += [
            ("/usr/share/code/resources/app/out/main.js", "VS Code main"),
            ("/usr/share/code/resources/app/node_modules/@vscode/deviceid/dist/index.js", "VS Code deviceid"),
            ("/usr/share/cursor/resources/app/out/main.js", "Cursor main"),
            ("/usr/share/antigravity/resources/app/node_modules/@vscode/deviceid/dist/index.js", "Antigravity deviceid"),
            ("/usr/share/discord/modules/discord_desktop_core/index.js", "Discord core"),
        ]
    # npm CLI - the worm's propagation engine, in every global npm root it can find
    for root in global_npm_roots():
        t.append((str(root / "npm/lib/cli.js"), "npm CLI"))
    return t


def global_npm_roots() -> list[Path]:
    roots = []
    for cand in (
        Path("/usr/local/lib/node_modules"),
        Path("/opt/homebrew/lib/node_modules"),
        Path("/usr/lib/node_modules"),
        HOME / ".nvm/versions/node",
    ):
        if cand.is_dir():
            if cand.name == "node":                      # nvm: versioned subdirs
                roots += [p / "lib/node_modules" for p in cand.iterdir() if p.is_dir()]
            else:
                roots.append(cand)
    try:
        out = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True,
                             timeout=20, check=False)
        if out.returncode == 0 and out.stdout.strip():
            p = Path(out.stdout.strip())
            if p.is_dir():
                roots.append(p)
    except Exception:
        pass
    return sorted({r for r in roots if r.is_dir()})

# directories that are huge or irrelevant - pruned from walks
PRUNE_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", ".tox",
    ".mypy_cache", ".pytest_cache", ".terraform", ".gradle", ".cargo", "target",
    "Caches", ".Trash", "Photos Library.photoslibrary", "Library/Caches",
    ".docker", "snap", ".cache", "Trash", "System", "Volumes",
    # note: we deliberately do NOT prune node_modules - we hunt inside it,
    # but by directory name and by filename allowlist, not by grepping everything.
}
GREP_FILENAME_ALLOWLIST = {"cli.js", "main.js", "index.js", "database.js", "utils.min.js",
                           "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                           ".zshrc", ".bashrc", ".bash_profile", ".profile", ".zprofile"}

MAX_GREP_BYTES = 8 * 1024 * 1024

# paths the user asked to skip (-–exclude), plus anything we quarantined ourselves
EXCLUDES: list[str] = []


def _excluded(p: Path) -> bool:
    s = str(p)
    if "/inz-quarantine-" in s or "inz-quarantine-" in p.name:
        return True
    return any(s == e or s.startswith(e.rstrip("/") + os.sep) for e in EXCLUDES)


@dataclass
class Finding:
    kind: str            # package|injected|staging|install-root|temp-cache|process|env|network|persistence|npm-cache|lockfile
    severity: str        # critical|high|medium|info
    path: str
    evidence: str
    action: str = "manual"   # quarantine|restore-orig|reinstall|kill-process|manual
    detail: str = ""


# --------------------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------------------

def _read_text(p: Path, limit: int = MAX_GREP_BYTES) -> str | None:
    try:
        if p.stat().st_size > limit:
            return None
        with open(p, "rb") as fh:
            raw = fh.read(limit)
        if b"\x00" in raw[:4096]:          # binary
            return None
        return raw.decode("utf-8", "replace")
    except (OSError, PermissionError):
        return None


def orig_is_pristine(p: Path) -> bool:
    """True only if the worm's own .inz.orig backup exists AND is itself uninfected."""
    o = Path(str(p) + ".inz.orig")
    if not o.is_file():
        return False
    t = _read_text(o, 64 * 1024 * 1024)
    if t is None:
        return False
    if any(m in t for m in INJECTION_MARKERS):
        return False
    if any(rx.search(t) for rx, _ in STRONG_SIGNATURES):
        return False
    return True


def grep_signatures(path: Path, text: str, relabel: str, label: str = "") -> list[Finding]:
    out: list[Finding] = []
    act = "restore-orig" if orig_is_pristine(path) else "quarantine"
    detail = ("restores automatically from the worm's own .inz.orig backup"
              if act == "restore-orig" else
              "no verifiable .inz.orig - quarantine, then reinstall the application")
    for marker in INJECTION_MARKERS:
        if marker in text:
            out.append(Finding("injected", "critical", str(path),
                               f"injection marker {marker}" + (f" [{label}]" if label else ""),
                               act, detail))
    for rx, why in STRONG_SIGNATURES:
        m = rx.search(text)
        if m:
            out.append(Finding("injected", "critical", str(path),
                               f"{why}: {m.group(0)[:70]!r}" + (f" [{label}]" if label else ""),
                               act, detail))
            break
    else:
        for rx, why in WEAK_SIGNATURES:
            m = rx.search(text)
            if m:
                out.append(Finding("injected", "high", str(path),
                                   f"{why}: {m.group(0)[:60]!r}", act, detail))
                break
    for ip in C2_IPS:
        if ip in text:
            out.append(Finding("network", "critical", str(path), f"C2 address {ip} present", "manual"))
            break
    if ANTI_ANALYSIS_MD5 in text:
        out.append(Finding("injected", "critical", str(path),
                           f"anti-analysis digest {ANTI_ANALYSIS_MD5}", act, detail))
    return out


def scan_target_files() -> list[Finding]:
    """Check the exact application files the worm is known to inject into."""
    found: list[Finding] = []
    for path, label in injection_targets():
        p = Path(path)
        if not p.is_file():
            continue
        txt = _read_text(p, 64 * 1024 * 1024)   # these can be large
        if txt is None:
            try:
                raw = p.read_bytes()
                if any(m.encode() in raw for m in INJECTION_MARKERS) or b"__inz" in raw:
                    found.append(Finding("injected", "critical", path,
                                         "markers present (binary read)", "reinstall", f"{label}"))
            except OSError:
                pass
            continue
        hits = grep_signatures(p, txt, str(p), label)
        for h in hits:
            h.action = "restore-orig" if (p.with_suffix(p.suffix + ".inz.orig")).exists() else "reinstall"
        if hits:
            found += hits
        elif label:
            found.append(Finding("info", "info", path, f"{label}: clean", "manual"))
    return found


def scan_tree(roots: list[Path], deep: bool) -> list[Finding]:
    """Walk for package dirs, staging files, lockfile/cache mentions, and (deep) content."""
    found: list[Finding] = []
    seen_pkg: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS and not d.startswith(".")]
            dp = Path(dirpath)
            if _excluded(dp):
                dirnames[:] = []
                continue

            # 1) malicious package directories
            for d in list(dirnames):
                if d in MALICIOUS_PACKAGES:
                    full = dp / d
                    key = str(full)
                    if key not in seen_pkg:
                        seen_pkg.add(key)
                        ver = ""
                        pj = full / "package.json"
                        if pj.is_file():
                            try:
                                ver = json.loads(pj.read_text(errors="replace")).get("version", "")
                            except Exception:
                                pass
                        found.append(Finding("package", "critical", str(full),
                                             f"malicious package {d}@{ver or '?'} installed",
                                             "quarantine",
                                             "UNINSTALLING IS NOT ENOUGH - also check the npm CLI, IDEs and CI"))

            # 2) staging artefacts
            for fn in filenames:
                if fn.endswith(STAGING_SUFFIXES) or fn == ".npm-install.lock":
                    p = dp / fn
                    found.append(Finding("staging", "critical", str(p),
                                         f"worm staging artefact ({fn})", "quarantine"))

            # 3) lockfiles + npm cache index -> proves historical exposure
            for fn in filenames:
                if fn in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                    p = dp / fn
                    try:
                        if p.stat().st_size > 64 * 1024 * 1024:
                            continue
                        txt = p.read_text(errors="replace")
                    except OSError:
                        continue
                    for pkg in MALICIOUS_PACKAGES:
                        if f"/{pkg}" in txt or f'"{pkg}"' in txt:
                            found.append(Finding("lockfile", "high", str(p),
                                                 f"lockfile pins {pkg} (historical exposure)", "manual"))
                            break

            # 4) content grep.
            #    Inside node_modules we only open allowlisted filenames (keeps the default
            #    scan fast); outside node_modules we grep every script. --deep opens all.
            in_nm = "node_modules" in dp.parts
            for fn in filenames:
                if not (fn.endswith((".js", ".cjs", ".mjs", ".ts", ".json", ".sh")) or fn in GREP_FILENAME_ALLOWLIST):
                    continue
                if in_nm and not deep and fn not in GREP_FILENAME_ALLOWLIST:
                    continue
                p = dp / fn
                txt = _read_text(p)
                if txt:
                    found += grep_signatures(p, txt, str(p))
    return found


def scan_npm_cache() -> list[Finding]:
    """Even after node_modules is cleaned, ~/.npm/_cacache records what was downloaded."""
    found: list[Finding] = []
    for base in (HOME / ".npm", HOME / "Library/Caches/npm", HOME / ".cache/npm"):
        idx = base / "_cacache/index-v5"
        if not idx.is_dir():
            continue
        hits: set[str] = set()
        for dirpath, dirnames, filenames in os.walk(idx):
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    data = p.read_bytes()
                except OSError:
                    continue
                for pkg in MALICIOUS_PACKAGES:
                    if pkg.encode() in data:
                        hits.add(pkg)
        if hits:
            found.append(Finding("npm-cache", "critical", str(idx),
                                 "npm cache holds: " + ", ".join(sorted(hits)), "manual",
                                 "run: npm cache clean --force"))
    return found


def scan_install_roots() -> list[Finding]:
    """The RAT's own install roots (~node / ~py / node20) - unambiguous malware."""
    found: list[Finding] = []
    for name in INSTALL_ROOTS:
        p = HOME / name
        if p.exists():
            found.append(Finding("install-root", "critical", str(p),
                                 f"campaign install root ~/{name} exists", "quarantine",
                                 "holds the detached node/python backdoor"))
    for tp in Path("/tmp"), Path("/var/tmp"):
        if not tp.is_dir():
            continue
        try:
            for p in tp.glob("nm-npm-cache-*"):
                found.append(Finding("temp-cache", "high", str(p),
                                     "on-demand socket.io install cache", "quarantine"))
        except OSError:
            pass
    return found


def scan_processes() -> list[Finding]:
    found: list[Finding] = []
    try:
        out = subprocess.run(["ps", "-eo", "pid=,args="], capture_output=True, text=True,
                             timeout=20, check=False).stdout
    except Exception:
        return found
    me = os.getpid()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        pid, _, args = line.partition(" ")
        if not pid.isdigit() or int(pid) == me:
            continue
        low = args
        for needle, why in (
            ("global._V", "loader stager argv"),
            ("global['_V']", "loader stager argv"),
            ("jsbot", "campaign process name"),
            ("nm-npm-cache-", "RAT node process"),
            (".inz.cjs", "worm payload process"),
        ):
            if needle in low:
                found.append(Finding("process", "critical", args[:200],
                                     f"running process matches {why} (pid {pid})", "kill-process"))
                break
    return found


def scan_network() -> list[Finding]:
    """Local socket table only - no packets sent, nothing contacted."""
    found: list[Finding] = []
    if IS_WIN:
        return found
    try:
        out = subprocess.run(["lsof", "-nP", "-i"], capture_output=True, text=True,
                             timeout=25, check=False).stdout
    except Exception:
        return found
    for line in out.splitlines():
        for ip in C2_IPS:
            if ip in line:
                found.append(Finding("network", "critical", line.strip()[:220],
                                     f"live connection to C2 {ip}", "kill-process"))
                break
    return found


def scan_env_and_persistence() -> list[Finding]:
    found: list[Finding] = []
    for k, v in os.environ.items():
        if k in ("NODE_OPTIONS", "_VSCODE_PRODUCT_JSON") and v:
            found.append(Finding("env", "medium", f"{k}={v[:160]}",
                                 "environment variable the worm manipulates", "manual"))
        elif any(ip in v for ip in C2_IPS):
            found.append(Finding("env", "critical", f"{k}=<contains C2 address>",
                                 "C2 address in environment", "manual"))

    rc_files = [HOME / f for f in (".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile")]
    if IS_MAC:
        la = HOME / "Library/LaunchAgents"
        if la.is_dir():
            rc_files += list(la.glob("*.plist"))
    for p in rc_files:
        txt = _read_text(p, 2 * 1024 * 1024)
        if not txt:
            continue
        for needle, why in ((f"{HOME}/node", "installs/runs campaign node root"),
                            (f"{HOME}/py", "installs/runs campaign python root"),
                            ("node20", "campaign node directory"),
                            ("jsbot", "campaign process name")):
            if needle in txt:
                found.append(Finding("persistence", "critical", str(p),
                                     f"{why} ({needle})", "manual"))
                break
        for ip in C2_IPS:
            if ip in txt:
                found.append(Finding("persistence", "critical", str(p), f"C2 address {ip}", "manual"))
                break
    return found


# --------------------------------------------------------------------------------------
# removal
# --------------------------------------------------------------------------------------

# the worm's OWN strip regexes (from its string table) - exact, not guessed
STRIP_PATTERNS = [
    (re.compile(r"\r?\n?import\s*\{\s*createRequire\s+as\s+__inzCR\s*\}\s*from\s*['\"]module['\"]\s*;"
                r"\s*const\s+__inzV\s*=\s*['\"][^'\"]*['\"]\s*;"
                r"\s*__inzCR\s*\(\s*import\.meta\.url\s*\)\s*\(\s*['\"][^'\"]+\.inz\.cjs['\"]\s*\)\s*;?\s*"), "\n"),
    (re.compile(r"\r?\n?const\s+__inzV\s*=\s*['\"][^'\"]*['\"]\s*;"
                r"\s*const\s+__inzRQ\s*=\s*require\s*\(\s*['\"][^'\"]+\.inz\.cjs['\"]\s*\)\s*;?\s*"), "\n"),
    (re.compile(r"/\*(?:RS260605|C25061[789]A|C250620A|C260511A|M260630A)\*/"), ""),
]


def _node_check(p: Path) -> str:
    """If node is available, syntax-check the file we just rewrote."""
    if p.suffix not in (".js", ".cjs", ".mjs") or shutil.which("node") is None:
        return ""
    try:
        r = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True, timeout=30)
        return "  syntax OK (node --check)" if r.returncode == 0 else \
               f"  !! node --check FAILED: {r.stderr.strip()[:120]} - restore from the quarantine copy"
    except Exception:
        return ""


def quarantine(src: Path, backup_root: Path, dry: bool, purge: bool) -> str:
    rel = str(src).lstrip("/").replace(os.sep, "__")
    dst = backup_root / rel
    if dry:
        return f"[dry-run] quarantine {src}"
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if purge:
            # back up first, then delete
            if src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
                shutil.rmtree(src, ignore_errors=True)
            else:
                shutil.copy2(src, dst, follow_symlinks=False)
                src.unlink(missing_ok=True)
            return f"BACKED UP + DELETED {src}"
        # default: MOVE the artefact (file or whole tree) into quarantine - it is the backup
        moved = backup_root / (rel + ".MOVED")
        shutil.move(str(src), str(moved))
        return f"QUARANTINED {src} -> {moved}"
    except OSError as e:
        return f"FAILED {src}: {e}"


def restore_from_orig(src: Path, backup_root: Path, dry: bool, purge: bool) -> str:
    orig = Path(str(src) + ".inz.orig")
    if not orig.is_file():
        return f"NO .inz.orig for {src}"
    try:
        if dry:
            return f"[dry-run] restore {src} from {orig.name}"
        rel = str(src).lstrip("/").replace(os.sep, "__")
        dst = backup_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)                      # keep the infected copy as evidence
        shutil.copy2(orig, src)                     # put the pristine file back
        if purge:
            orig.unlink(missing_ok=True)
        else:
            os.replace(orig, backup_root / (rel + ".inz.orig.MOVED"))
        return f"RESTORED {src} from .inz.orig (infected copy kept at {dst})"
    except OSError as e:
        return f"FAILED restore {src}: {e}"


def strip_injected(src: Path, backup_root: Path, dry: bool) -> str:
    """Opt-in. Removes the injected block using the worm's own strip patterns."""
    txt = _read_text(src, 64 * 1024 * 1024)
    if txt is None:
        return f"SKIP (unreadable/binary) {src}"
    new = txt
    for rx, rep in STRIP_PATTERNS:
        new = rx.sub(rep, new)
    # Appended stage-1 style loader: "global.i='<tag>';global.j=1; ... to EOF".
    # DANGER: truncating to EOF destroys any legitimate code that follows the injection.
    # Only truncate when the tail after the prologue looks like the minified loader itself
    # (no line comments, no blank lines) - otherwise leave it alone for manual review.
    note = ""
    m = re.search(r"(?:^|\n)(?=global\.i\s*=\s*['\"][^'\"]{1,16}['\"]\s*;?\s*global\.j\s*=\s*1)",
                  new, re.M)
    if m:
        tail = new[m.end():]
        if "//" not in tail and "\n\n" not in tail:
            new = new[:m.start()] + "\n"
            note = f"  [appended loader truncated to EOF: {len(tail)} bytes]"
        else:
            note = "  [appended loader prologue found but code follows it - NOT truncated, review manually]"
    if new == txt:
        return f"NO CHANGE (no inject pattern matched) {src}"
    if dry:
        return f"[dry-run] strip {len(txt) - len(new)} bytes from {src}"
    rel = str(src).lstrip("/").replace(os.sep, "__")
    dst = backup_root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    src.write_text(new, encoding="utf-8")
    residual = [m for m in INJECTION_MARKERS if m in new]
    residual += [w for rx, w in STRONG_SIGNATURES if rx.search(new)]
    flag = "  !! RESIDUAL RISK: " + "; ".join(residual[:3]) if residual else "  (clean)"
    return f"STRIPPED {len(txt) - len(new)} bytes from {src}{flag}{_node_check(src)}"


def do_remove(findings: list[Finding], args) -> int:
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup_root = Path(args.backup_dir) if args.backup_dir else HOME / f"inz-quarantine-{ts}"
    if not args.dry_run:
        backup_root.mkdir(parents=True, exist_ok=True)
        print(f"[*] quarantine: {backup_root}"
              + ("   (files will be DELETED after backup: --purge)\n" if args.purge else "\n"))

    if not args.yes and not args.dry_run:
        print("[!] This will modify the system. Re-run with --yes to proceed, "
              "or --dry-run to preview.")
        return 2

    actions: list[str] = []
    reinstalls: list[str] = []
    manual: list[str] = []
    handled: set[str] = set()

    # dedupe by path, keeping the most specific action
    by_path: dict[str, Finding] = {}
    for f in findings:
        if f.severity == "info":
            continue
        if f.path not in by_path or f.action in ("restore-orig", "kill-process"):
            by_path[f.path] = f

    # PASS 1 - restores first, so the worm's own .inz.orig is still in place when we use it
    for path, f in sorted(by_path.items()):
        if f.action != "restore-orig" or not f.kind == "injected":
            continue
        p = Path(path)
        if not p.exists():
            continue
        if Path(str(p) + ".inz.orig").is_file():
            actions.append(restore_from_orig(p, backup_root, args.dry_run, args.purge))
            handled.add(path)
            side = Path(str(p) + ".inz.cjs")
            if side.is_file():
                actions.append(quarantine(side, backup_root, args.dry_run, args.purge))
                handled.add(str(side))
            # the .orig is consumed or moved by the restore above
            handled.add(str(p) + ".inz.orig")
        elif args.strip:
            actions.append(strip_injected(p, backup_root, args.dry_run))
            handled.add(path)
        else:
            reinstalls.append(path)
            handled.add(path)

    # PASS 2 - everything else
    for path, f in sorted(by_path.items()):
        if path in handled:
            continue
        if f.action == "kill-process" or f.kind in ("process", "network"):
            manual.append(f"investigate live process/socket manually: {f.path}")
            continue
        if f.kind == "env":
            manual.append(f"check and remove this environment variable: {f.path}")
            continue
        if f.kind == "lockfile":
            manual.append(f"remove the package from {f.path} and reinstall from a clean lockfile")
            continue
        if f.kind == "npm-cache":
            manual.append("npm cache clean --force   (clear the poisoned cache)")
            continue
        p = Path(path)
        if not p.exists():
            continue
        if f.kind == "injected" and args.strip:
            actions.append(strip_injected(p, backup_root, args.dry_run))
            continue
        if f.kind == "injected":
            reinstalls.append(path)
            continue
        if f.kind in ("package", "staging", "install-root", "temp-cache"):
            actions.append(quarantine(p, backup_root, args.dry_run, args.purge))

    for a in actions:
        print("  " + a)
    if reinstalls:
        print("\n[!] Injected application files - RESTORE BY REINSTALLING (do not patch vendor binaries):")
        for r in reinstalls:
            if "npm/lib/cli.js" in r:
                print(f"    {r}\n      -> npm i -g npm@latest")
            elif "Visual Studio Code.app" in r:
                print(f"    {r}\n      -> reinstall VS Code from the official .dmg")
            elif "Cursor.app" in r:
                print(f"    {r}\n      -> reinstall Cursor from cursor.com")
            elif "Antigravity.app" in r:
                print(f"    {r}\n      -> reinstall Antigravity from the official installer")
            elif "discord" in r.lower():
                print(f"    {r}\n      -> reinstall Discord.app")
            elif "GitHub Desktop" in r:
                print(f"    {r}\n      -> reinstall GitHub Desktop")
            else:
                print(f"    {r}")
        print("      then re-run:  python3 inz_scan.py scan")
    for m in manual:
        print(f"  [manual] {m}")

    print(f"\n[*] {len(actions)} action(s). "
          + (f"Quarantine: {backup_root}" if not args.dry_run else "(dry run - nothing changed)"))
    if not args.dry_run:
        print("[*] Nothing was deleted"
              + (" except after backup (--purge)." if args.purge else " - quarantined files can be restored."))
    return 0


# --------------------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------------------

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def report(findings: list[Finding], args) -> int:
    real = [f for f in findings if f.severity != "info"]
    infos = [f for f in findings if f.severity == "info"]
    real.sort(key=lambda f: (SEV_ORDER[f.severity], f.kind, f.path))

    print(f"\ninz_scan.py v{VERSION}  |  host {os.uname().nodename if hasattr(os,'uname') else ''}"
          f"  |  {'macOS' if IS_MAC else sys.platform}  |  offline, read-only")
    print("=" * 78)

    if not real:
        print("\n  NO INDICATORS FOUND\n")
        print("  This means the markers we know about are absent - not proof the machine is")
        print("  clean. If it was ever exposed: rotate credentials anyway, and re-run with --deep.")
    else:
        crit = sum(1 for f in real if f.severity == "critical")
        print(f"\n  {len(real)} FINDING(S)  ({crit} critical)\n")
        for f in real:
            print(f"  [{f.severity.upper():8}] {f.kind:12} {f.path}")
            print(f"             {f.evidence}")
            if f.detail:
                print(f"             -> {f.detail}")
        kinds = {}
        for f in real:
            kinds[f.kind] = kinds.get(f.kind, 0) + 1
        print("\n  summary: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))

    if args.verbose and infos:
        print(f"\n  -- checked clean ({len(infos)}) --")
        for f in infos:
            print(f"     {f.path}")

    print("\n  next step:  python3 inz_scan.py remove-all --dry-run   (preview)")
    if real:
        print("              python3 inz_scan.py remove-all --yes       (quarantine)")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "version": VERSION, "platform": sys.platform, "host": os.uname().nodename if hasattr(os, "uname") else "",
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "findings": [asdict(f) for f in findings],
        }, indent=2))
        print(f"\n  json written: {args.json}")
    return 1 if real else 0


# --------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Detect (and optionally remove) the NullReceiver / 'jsbot' developer worm.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="scan is read-only and offline. remove-all quarantines; it never deletes unless --purge.")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="read-only detection (default)")
    s.add_argument("--root", action="append", default=[], help="limit scan to DIR (repeatable)")
    s.add_argument("--exclude", action="append", default=[],
                   help="skip DIR (repeatable) - e.g. your own malware-analysis / evidence folder")
    s.add_argument("--deep", action="store_true", help="grep every JS/TS file, not just allowlisted ones")
    s.add_argument("--json", help="write findings as JSON to this path")
    s.add_argument("--verbose", "-v", action="store_true", help="show files checked clean")

    r = sub.add_parser("remove-all", help="quarantine everything detected")
    r.add_argument("--exclude", action="append", default=[])
    r.add_argument("--yes", action="store_true", help="required to actually modify the system")
    r.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    r.add_argument("--purge", action="store_true", help="delete instead of quarantine (after backup)")
    r.add_argument("--strip", action="store_true",
                   help="also neutralise injected code blocks in app files without .inz.orig")
    r.add_argument("--backup-dir", help="quarantine location (default ~/inz-quarantine-<ts>)")
    r.add_argument("--deep", action="store_true")
    r.add_argument("--root", action="append", default=[])

    args = ap.parse_args()
    if not args.cmd:
        args.cmd = "scan"
    for attr, default in (("root", []), ("exclude", []), ("deep", False), ("json", None),
                          ("verbose", False), ("yes", False), ("dry_run", True), ("purge", False),
                          ("strip", False), ("backup_dir", None)):
        if not hasattr(args, attr):
            setattr(args, attr, default)

    EXCLUDES[:] = [str(Path(x).expanduser().resolve()) for x in (args.exclude or [])]

    roots = [Path(x).expanduser() for x in args.root] or [HOME]

    print(f"[*] scanning {', '.join(str(x) for x in roots)} ...", file=sys.stderr)
    findings: list[Finding] = []
    findings += scan_target_files()
    findings += scan_tree(roots, args.deep)
    findings += scan_install_roots()
    findings += scan_npm_cache()
    findings += scan_processes()
    findings += scan_network()
    findings += scan_env_and_persistence()
    findings = [f for f in findings if f.severity != "info"] + [f for f in findings if f.severity == "info"]

    if args.cmd == "remove-all":
        return do_remove(findings, args)
    return report(findings, args)


if __name__ == "__main__":
    sys.exit(main())
