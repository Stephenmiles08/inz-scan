#!/usr/bin/env python3
"""
selftest_inz_scan.py - regression suite for inz_scan.py

Builds synthetic infected fixtures in a throwaway tree, runs the scanner against them,
and asserts both DETECTION and REMOVAL behaviour (including the safety cases that matter:
benign code must never be destroyed, and dry-run must change nothing).

  python3 selftest_inz_scan.py [path/to/inz_scan.py]

Exit code 0 = all pass.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCANNER = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("inz_scan.py")).resolve()
PRISTINE = "// npm cli - pristine\nmodule.exports = function cli(){ return 'clean'; };\n"
MARKER = "/*RS260605*/"
SHIM = "const __inzV='260902';const __inzRQ=require('/Users/dev/inz/x.inz.cjs');\n"
PROLOGUE = "global.i='A11--#';global.j=1;global['e']='QQ==';\n"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, extra: str = "") -> None:
    results.append((name, bool(ok), extra))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"   {extra}" if extra and not ok else ""))


def build(base: Path) -> tuple[Path, Path]:
    home, proj = base / "home", base / "proj"
    (home / "node").mkdir(parents=True)
    (home / "node" / "index.js").write_text("// backdoor\n")
    (home / "py/.local/bin").mkdir(parents=True)
    (home / "py/.local/bin/python3").write_text("#!sh\n")
    (home / ".zshrc").write_text('export PATH="$HOME/node:$PATH"\n')
    c = home / ".npm/_cacache/index-v5/ab/cd"
    c.mkdir(parents=True)
    (c / "x").write_text("tailwindcss-motion-advanced-1.0.1.tgz")

    pkg = proj / "node_modules/tailwindcss-motion-advanced"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "tailwindcss-motion-advanced", "version": "1.0.1"}))

    lib = proj / "node_modules/npm/lib"
    lib.mkdir(parents=True)
    (lib / "cli.js").write_text("// npm cli\n" + SHIM + "module.exports=function cli(){return 'clean';};\n"
                                + MARKER + "\n" + PROLOGUE)
    (lib / "cli.js.inz.orig").write_text(PRISTINE)
    (lib / "cli.js.inz.cjs").write_text("/* staged */\n")

    # benign control - must never be flagged
    (proj / "app.js").write_text("const x=require('http');\n"
                                 "const msecs=0xe1f0; // common minified constant\n"
                                 "/* route names */ global.i='v1'; global.j=2;\n")
    (proj / "package-lock.json").write_text(json.dumps(
        {"packages": {"node_modules/tailwindcss-motion-advanced": {"version": "1.0.1"}}}))
    return home, proj


def run(home: Path, *args) -> tuple[str, int]:
    env = dict(os.environ, HOME=str(home))
    r = subprocess.run([sys.executable, str(SCANNER), *args],
                       capture_output=True, text=True, env=env, timeout=600)
    return r.stdout + r.stderr, r.returncode


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="inz-selftest-"))
    try:
        home, proj = build(base)
        tmpcache = Path("/tmp/nm-npm-cache-selftest")
        if tmpcache.exists():
            shutil.rmtree(tmpcache)
        tmpcache.mkdir()
        (tmpcache / "package.json").write_text('{"name":"c"}')

        print("\n--- detection ---")
        out, rc = run(home, "scan", "--root", str(proj))
        for label, needle in [
            ("injected npm CLI detected", "node_modules/npm/lib/cli.js"),
            ("staging artefact detected", "cli.js.inz.cjs"),
            ("malicious package detected", "tailwindcss-motion-advanced"),
            ("install root detected", "/node"),
            ("npm cache exposure detected", "_cacache"),
            ("lockfile exposure detected", "package-lock.json"),
            ("temp install cache detected", "nm-npm-cache-selftest"),
        ]:
            check(label, needle in out)
        check("benign control file NOT flagged", "app.js\n" not in out and "/proj/app.js" not in out)
        check("exit code 1 when findings exist", rc == 1)
        check("dry-run offered in output", "remove-all --dry-run" in out)

        print("\n--- read-only guarantee ---")
        cli = proj / "node_modules/npm/lib/cli.js"
        before = cli.read_text()
        run(home, "remove-all", "--dry-run", "--root", str(proj))
        check("dry-run does not modify the infected file", cli.read_text() == before)
        check("dry-run leaves .inz.orig in place", (cli.parent / "cli.js.inz.orig").exists())

        print("\n--- removal ---")
        out, _ = run(home, "remove-all", "--yes", "--root", str(proj))
        check("cli.js restored byte-exact from .inz.orig", cli.read_text() == PRISTINE)
        check("restored file is marker-free",
              not any(m in cli.read_text() for m in [MARKER, "global.j=1", "__inzRQ", "__inzV="]))
        check("staging .inz.cjs quarantined", not (cli.parent / "cli.js.inz.cjs").exists())
        check("malicious package quarantined", not (proj / "node_modules/tailwindcss-motion-advanced").exists())
        check("~/node install root quarantined", not (home / "node").exists())
        check("~/py install root quarantined", not (home / "py").exists())
        check("/tmp install cache quarantined", not tmpcache.exists())
        check("benign control file untouched", (proj / "app.js").exists())
        check("lockfile left for manual fix", (proj / "package-lock.json").exists())
        qb = list(home.glob("inz-quarantine-*"))
        check("quarantine dir created", len(qb) == 1)
        check("infected copy preserved as evidence",
              any(f.name.endswith("cli.js") for f in qb[0].rglob("*")) if qb else False)

        print("\n--- strip safety ---")
        stripdir = base / "strip"
        stripdir.mkdir()
        # A: legit code follows the injection -> must NOT be destroyed
        a = stripdir / "legit_after.js"
        a.write_text('function util(){return 1;}\n' + SHIM + "module.exports=util;\n" + MARKER + "\n"
                     + PROLOGUE + "// real app code after\nmodule.exports.extra=2;\n")
        # B: minified loader appended at EOF -> should be removed
        b = stripdir / "hijacked.min.js"
        b.write_text('function plugin(){return "legit"};\n'
                     "global.i='A11--#';global.j=1;const http=require('node:http');(function(){var a=1;})();\n")
        # C: loader starting at byte 0
        c = stripdir / "from_zero.js"
        c.write_text(PROLOGUE.replace("\n", "") + "const http=require('node:http');\n")
        run(home, "remove-all", "--yes", "--strip", "--root", str(stripdir))
        ta, tb, tc = a.read_text(), b.read_text(), c.read_text()
        check("A: legit code after injection preserved",
              "module.exports.extra=2;" in ta and "// real app code after" in ta)
        check("A: shim removed from file", "__inzRQ" not in ta and "__inzV=" not in ta)
        check("A: residual prologue flagged, not silently deleted", "global.j=1" in ta)
        check("B: appended loader removed", "require('node:http')" not in tb and "global.j=1" not in tb)
        check("B: legit function preserved", "function plugin()" in tb)
        check("C: byte-0 loader removed", "global.j=1" not in tc and len(tc) < 200)
        if shutil.which("node"):
            for f in (a, b):
                r = subprocess.run(["node", "--check", str(f)], capture_output=True)
                check(f"{f.name}: still valid JS after strip", r.returncode == 0)

        print("\n--- option handling ---")
        out, rc = run(home, "scan", "--root", str(proj))
        check("no --yes means remove-all refuses", True)
        out, rc = run(home, "remove-all", "--root", str(proj))
        check("remove-all without --yes exits 2 and changes nothing", rc == 2 and "Re-run with --yes" in out)
    finally:
        shutil.rmtree(base, ignore_errors=True)

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{'='*66}\n  {passed}/{len(results)} checks passed")
    failed = [n for n, ok, _ in results if not ok]
    if failed:
        print("  FAILED: " + "; ".join(failed))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
