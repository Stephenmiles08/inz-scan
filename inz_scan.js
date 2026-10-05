#!/usr/bin/env node
'use strict';
/**
 * inz_scan.js - detector + opt-in remover for the NullReceiver / "jsbot" developer worm
 *               (stage 2 of the tailwindcss-motion-advanced npm supply-chain loader)
 *
 * WHY THIS EXISTS: the victims of this campaign are Node developers, so they already have
 * node. That removes the only real preflight the Python build has (`python3`, which macOS
 * does not ship). Zero dependencies, no install step.
 *
 *   node inz_scan.js scan                     read-only detection (default)
 *   node inz_scan.js scan --deep
 *   node inz_scan.js scan --json out.json
 *   node inz_scan.js remove-all --dry-run     show exactly what removal would do
 *   node inz_scan.js remove-all --yes         quarantine (moves to a backup dir)
 *   node inz_scan.js remove-all --yes --strip also neutralise injected code blocks
 *
 * SAFETY RAILS (identical to the Python build):
 *   - makes ZERO network calls - it never contacts the C2 and never downloads anything
 *   - never executes, requires, imports or evaluates any file it finds - text scanning only
 *   - `scan` cannot write anything anywhere
 *   - `remove-all` QUARANTINES (moves to ~/inz-quarantine-<ts>/) instead of deleting
 *   - `remove-all` refuses to touch a file unless it matches a known infection signature
 *   - refuses to patch vendor binaries it cannot verify - prints the reinstall command instead
 *
 * Requires Node 14.14+. No dependencies.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const {execFileSync, spawnSync} = require('child_process');

const VERSION = '1.3';
const HOME = os.homedir();
const IS_MAC = process.platform === 'darwin';
const IS_WIN = process.platform === 'win32';

// ---------------------------------------------------------------------------------------
// Indicators of compromise (recovered from the live payload)
// ---------------------------------------------------------------------------------------

const MALICIOUS_PACKAGES = [
  'tailwindcss-motion-advanced', 'envpack-conf', 'postcss-initial-provider',
  'agentgui', 'godot-kit', 'fluid-type-ui', 'bianira-ui', '@kolbo/mcp',
];

const INJECTION_MARKERS = [
  '/*RS260605*/', '/*C250617A*/', '/*C250618A*/', '/*C250619A*/',
  '/*C250620A*/', '/*C260511A*/', '/*M260630A*/',
];

const STRONG_SIGNATURES = [
  [/global\.i\s*=\s*['"][^'"]{1,16}['"]\s*;?\s*global\.j\s*=\s*1/, 'injected loader prologue (global.i / global.j=1)'],
  [/createRequire\s+as\s+__inzCR/, 'ESM injection shim (__inzCR)'],
  [/const\s+__inzV\s*=\s*['"]/, 'injection version constant (__inzV)'],
  [/__inzRQ\s*=\s*require\s*\(/, 'CJS injection hook (__inzRQ)'],
  [/\.inz\.cjs/, 'staged payload reference (.inz.cjs)'],
  [/x-payload-b64/, 'loader fallback header'],
  [/0xa322e5f3d311d3080e6f0121063e9adc2490ef1a/i, 'NullReceiver dead-drop wallet'],
  [/[\\/]0x[\\/](cl|cb|js)|\$[\\/]boot|verify-human/, 'C2 endpoint path'],
  [/ss_eval64|ss_upf|ss_fcd|ss_inzx:/, 'RAT command names'],
  [/nm-npm-cache-/, 'on-demand socket.io install cache'],
];

const WEAK_SIGNATURES = [
  [/\bSec-V\b/, 'loader beacon header (Sec-V)'],
  [/socket\.io-client@4\.7\.5/, 'pinned socket.io-client version'],
  [/\bglobal\.j\s*=\s*1\b/, 'infection marker (global.j=1)'],
];

const C2_IPS = ['91.218.183.174', '166.88.134.75', '193.247.144.38'];
const STAGING_SUFFIXES = ['.inz.cjs', '.inz.orig', '.inz.tmp'];
const INSTALL_ROOTS = ['node', 'py', 'node20', '.node', '~node', '~py'];
const ANTI_ANALYSIS_MD5 = '9a47bb48b7b8ca41fc138fd3372e8cc0';

const PRUNE_DIRS = new Set([
  '.git', '.hg', '.svn', '__pycache__', '.venv', 'venv', 'env', '.tox',
  '.mypy_cache', '.pytest_cache', '.terraform', '.gradle', '.cargo', 'target',
  'Caches', '.Trash', 'Photos Library.photoslibrary', '.docker', 'snap', '.cache',
  'Trash', 'System', 'Volumes',
]);

const GREP_FILENAME_ALLOWLIST = new Set([
  'cli.js', 'main.js', 'index.js', 'database.js', 'utils.min.js',
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  '.zshrc', '.bashrc', '.bash_profile', '.profile', '.zprofile',
]);

const SCRIPT_EXT = new Set(['.js', '.cjs', '.mjs', '.ts', '.json', '.sh']);
const MAX_GREP_BYTES = 8 * 1024 * 1024;

// paths to skip (--exclude), plus anything we quarantined ourselves
let EXCLUDES = [];
function isExcluded(p) {
  if (p.indexOf('inz-quarantine-') !== -1) return true;
  const s = path.resolve(p);
  return EXCLUDES.some((e) => s === e || s.startsWith(e + path.sep));
}

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

function tracking() {
  return {findings: [], seenPkg: new Set()};
}

function addFinding(t, kind, severity, p, evidence, action, detail) {
  t.findings.push({
    kind, severity, path: String(p), evidence,
    action: action || 'manual', detail: detail || '',
  });
}

function readText(p, limit) {
  limit = limit || MAX_GREP_BYTES;
  try {
    const st = fs.statSync(p);
    if (!st.isFile() || st.size > limit) return null;
    const fd = fs.openSync(p, 'r');
    const buf = Buffer.allocUnsafe(Math.min(st.size, limit));
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    const b = buf.slice(0, n);
    if (b.slice(0, 4096).indexOf(0) !== -1) return null; // binary
    return b.toString('utf8');
  } catch (e) {
    return null;
  }
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function origIsPristine(p) {
  const o = p + '.inz.orig';
  if (!fs.existsSync(o)) return false;
  const t = readText(o, 64 * 1024 * 1024);
  if (t === null) return false;
  if (INJECTION_MARKERS.some((m) => t.indexOf(m) !== -1)) return false;
  if (STRONG_SIGNATURES.some(([rx]) => rx.test(t))) return false;
  return true;
}

function grepSignatures(p, text, label) {
  const out = [];
  const action = origIsPristine(p) ? 'restore-orig' : 'quarantine';
  const detail = action === 'restore-orig'
    ? "restores automatically from the worm's own .inz.orig backup"
    : 'no verifiable .inz.orig - quarantine, then reinstall the application';
  const suffix = label ? ' [' + label + ']' : '';

  for (const m of INJECTION_MARKERS) {
    if (text.indexOf(m) !== -1) {
      out.push({kind: 'injected', severity: 'critical', path: p,
        evidence: 'injection marker ' + m + suffix, action, detail});
    }
  }
  let strong = false;
  for (const [rx, why] of STRONG_SIGNATURES) {
    const mm = rx.exec(text);
    if (mm) {
      out.push({kind: 'injected', severity: 'critical', path: p,
        evidence: why + ': ' + JSON.stringify(mm[0].slice(0, 70)) + suffix, action, detail});
      strong = true;
      break;
    }
  }
  if (!strong) {
    for (const [rx, why] of WEAK_SIGNATURES) {
      const mm = rx.exec(text);
      if (mm) {
        out.push({kind: 'injected', severity: 'high', path: p,
          evidence: why + ': ' + JSON.stringify(mm[0].slice(0, 60)), action, detail});
        break;
      }
    }
  }
  for (const ip of C2_IPS) {
    if (text.indexOf(ip) !== -1) {
      out.push({kind: 'network', severity: 'critical', path: p,
        evidence: 'C2 address ' + ip + ' present', action: 'manual', detail: ''});
      break;
    }
  }
  if (text.indexOf(ANTI_ANALYSIS_MD5) !== -1) {
    out.push({kind: 'injected', severity: 'critical', path: p,
      evidence: 'anti-analysis digest ' + ANTI_ANALYSIS_MD5, action, detail});
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// scanning
// ---------------------------------------------------------------------------------------

function globalNpmRoots() {
  const roots = [];
  const cands = IS_WIN
    ? [path.join(process.env.APPDATA || '', 'npm', 'node_modules')]
    : ['/usr/local/lib/node_modules', '/opt/homebrew/lib/node_modules',
       '/usr/lib/node_modules', path.join(HOME, '.nvm', 'versions', 'node')];
  for (const c of cands) {
    try {
      if (!fs.existsSync(c) || !fs.statSync(c).isDirectory()) continue;
      if (path.basename(c) === 'node') {
        for (const v of fs.readdirSync(c)) {
          const r = path.join(c, v, 'lib', 'node_modules');
          if (fs.existsSync(r)) roots.push(r);
        }
      } else roots.push(c);
    } catch (e) { /* ignore */ }
  }
  try {
    const out = execFileSync('npm', ['root', '-g'], {encoding: 'utf8', timeout: 20000, stdio: ['ignore', 'pipe', 'ignore']});
    const p = out.trim();
    if (p && fs.existsSync(p)) roots.push(p);
  } catch (e) { /* npm may not be present */ }
  return Array.from(new Set(roots)).filter((r) => {
    try { return fs.statSync(r).isDirectory(); } catch (e) { return false; }
  });
}

// `platform` overrides the FIXED application-path list only (that is the part that differs by OS,
// and the part the test suite can assert). The trailing npm-root entries always come from
// globalNpmRoots(), which inspects the real filesystem and the real `npm root -g` - you cannot
// enumerate another OS's npm installs, so that part is deliberately not simulated.
function injectionTargets(platform) {
  const mac = (platform || process.platform) === 'darwin';
  const t = [];
  if (mac) {
    t.push(['/Applications/Visual Studio Code.app/Contents/Resources/app/out/main.js', 'VS Code main']);
    t.push(['/Applications/Visual Studio Code.app/Contents/Resources/app/node_modules/@vscode/deviceid/dist/index.js', 'VS Code deviceid']);
    t.push(['/Applications/Cursor.app/Contents/Resources/app/out/main.js', 'Cursor main']);
    t.push(['/Applications/Cursor.app/Contents/Resources/app/node_modules/@vscode/deviceid/dist/index.js', 'Cursor deviceid']);
    t.push(['/Applications/Antigravity.app/Contents/Resources/app/node_modules/@vscode/deviceid/dist/index.js', 'Antigravity deviceid']);
    t.push(['/Applications/GitHub Desktop.app/Contents/Resources/app/main.js', 'GitHub Desktop main']);
    t.push([path.join(HOME, 'Library/Application Support/discord/modules/discord_desktop_core/index.js'), 'Discord core']);
    t.push([path.join(HOME, 'Library/Application Support/discord/modules/discord_desktop_core-1/discord_desktop_core/index.js'), 'Discord core (-1)']);
  } else {
    t.push(['/usr/share/code/resources/app/out/main.js', 'VS Code main']);
    t.push(['/usr/share/code/resources/app/node_modules/@vscode/deviceid/dist/index.js', 'VS Code deviceid']);
    t.push(['/usr/share/cursor/resources/app/out/main.js', 'Cursor main']);
    t.push(['/usr/share/antigravity/resources/app/node_modules/@vscode/deviceid/dist/index.js', 'Antigravity deviceid']);
    t.push(['/usr/share/discord/modules/discord_desktop_core/index.js', 'Discord core']);
  }
  for (const root of globalNpmRoots()) t.push([path.join(root, 'npm/lib/cli.js'), 'npm CLI']);
  return t;
}

function scanTargetFiles(t) {
  for (const [p, label] of injectionTargets()) {
    let st;
    try { st = fs.statSync(p); } catch (e) { continue; }
    if (!st.isFile()) continue;
    const txt = readText(p, 64 * 1024 * 1024);
    if (txt === null) continue;
    const hits = grepSignatures(p, txt, label);
    for (const h of hits) {
      h.action = fs.existsSync(p + '.inz.orig') && origIsPristine(p) ? 'restore-orig' : 'reinstall';
      t.findings.push(h);
    }
  }
}

function walkRoot(root, deep, t) {
  let entries;
  try { entries = fs.readdirSync(root, {withFileTypes: true}); } catch (e) { return; }
  for (const ent of entries) {
    const full = path.join(root, ent.name);
    if (isExcluded(full)) continue;

    let name = ent.name;
    let isDir = ent.isDirectory();
    let isFile = ent.isFile();
    if (ent.isSymbolicLink()) {           // don't follow symlinked dirs (matches os.walk followlinks=False)
      try {
        const st = fs.statSync(full);
        isDir = false;                    // never recurse through a link
        isFile = st.isFile();
      } catch (e) { continue; }
    }

    if (isDir) {
      if (MALICIOUS_PACKAGES.indexOf(name) !== -1 && !t.seenPkg.has(full)) {
        t.seenPkg.add(full);
        let ver = '?';
        try {
          ver = JSON.parse(fs.readFileSync(path.join(full, 'package.json'), 'utf8')).version || '?';
        } catch (e) { /* no package.json */ }
        addFinding(t, 'package', 'critical', full,
          'malicious package ' + name + '@' + ver + ' installed', 'quarantine',
          'UNINSTALLING IS NOT ENOUGH - also check the npm CLI, IDEs and CI');
      }
      if (name.charAt(0) !== '.' && !PRUNE_DIRS.has(name)) walkRoot(full, deep, t);
      continue;
    }
    if (!isFile) continue;

    // staging artefacts
    if (STAGING_SUFFIXES.some((s) => name.endsWith(s)) || name === '.npm-install.lock') {
      addFinding(t, 'staging', 'critical', full, 'worm staging artefact (' + name + ')', 'quarantine', '');
    }

    // lockfiles -> historical exposure
    if (name === 'package-lock.json' || name === 'yarn.lock' || name === 'pnpm-lock.yaml') {
      const txt = readText(full, 64 * 1024 * 1024);
      if (txt !== null) {
        for (const pkg of MALICIOUS_PACKAGES) {
          if (txt.indexOf('/' + pkg) !== -1 || txt.indexOf('"' + pkg + '"') !== -1) {
            addFinding(t, 'lockfile', 'high', full,
              'lockfile pins ' + pkg + ' (historical exposure)', 'manual', '');
            break;
          }
        }
      }
    }

    // content grep: inside node_modules only allowlisted filenames unless --deep
    const ext = path.extname(name).toLowerCase();
    if (!SCRIPT_EXT.has(ext) && !GREP_FILENAME_ALLOWLIST.has(name)) continue;
    const inNm = full.split(path.sep).indexOf('node_modules') !== -1;
    if (inNm && !deep && !GREP_FILENAME_ALLOWLIST.has(name)) continue;
    const txt = readText(full);
    if (txt === null) continue;
    for (const f of grepSignatures(full, txt, '')) t.findings.push(f);
  }
}

function scanInstallRoots(t) {
  for (const n of INSTALL_ROOTS) {
    const p = path.join(HOME, n);
    if (fs.existsSync(p)) {
      addFinding(t, 'install-root', 'critical', p,
        'campaign install root ~/' + n + ' exists', 'quarantine',
        'holds the detached node/python backdoor');
    }
  }
  for (const dir of ['/tmp', '/var/tmp']) {
    let ents;
    try { ents = fs.readdirSync(dir); } catch (e) { continue; }
    for (const e of ents) {
      if (e.indexOf('nm-npm-cache-') === 0) {
        addFinding(t, 'temp-cache', 'high', path.join(dir, e),
          'on-demand socket.io install cache', 'quarantine', '');
      }
    }
  }
}

function scanNpmCache(t) {
  for (const base of [path.join(HOME, '.npm'), path.join(HOME, 'Library/Caches/npm'), path.join(HOME, '.cache/npm')]) {
    const idx = path.join(base, '_cacache', 'index-v5');
    if (!fs.existsSync(idx)) continue;
    const hits = new Set();
    (function walk(d) {
      let ents;
      try { ents = fs.readdirSync(d, {withFileTypes: true}); } catch (e) { return; }
      for (const e of ents) {
        const f = path.join(d, e.name);
        if (e.isDirectory()) { walk(f); continue; }
        let buf;
        try { buf = fs.readFileSync(f); } catch (er) { continue; }
        for (const pkg of MALICIOUS_PACKAGES) if (buf.indexOf(pkg) !== -1) hits.add(pkg);
      }
    })(idx);
    if (hits.size) {
      addFinding(t, 'npm-cache', 'critical', idx,
        'npm cache holds: ' + Array.from(hits).sort().join(', '), 'manual',
        'run: npm cache clean --force');
    }
  }
}

function scanProcesses(t) {
  let out;
  try {
    out = execFileSync('ps', ['-Ao', 'pid=,args='], {encoding: 'utf8', timeout: 20000, stdio: ['ignore', 'pipe', 'ignore']});
  } catch (e) { return; }
  const me = process.pid;
  for (const line of out.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    const sp = s.indexOf(' ');
    if (sp < 0) continue;
    const pid = parseInt(s.slice(0, sp), 10);
    if (!pid || pid === me) continue;
    const args = s.slice(sp + 1);
    const needles = [['global._V', 'loader stager argv'], ["global['_V']", 'loader stager argv'],
                     ['jsbot', 'campaign process name'], ['nm-npm-cache-', 'RAT node process'],
                     ['.inz.cjs', 'worm payload process']];
    for (const [needle, why] of needles) {
      if (args.indexOf(needle) !== -1) {
        addFinding(t, 'process', 'critical', args.slice(0, 200),
          'running process matches ' + why + ' (pid ' + pid + ')', 'kill-process', '');
        break;
      }
    }
  }
}

function scanNetwork(t) {
  if (IS_WIN) return;
  let out;
  try {
    out = execFileSync('lsof', ['-nP', '-i'], {encoding: 'utf8', timeout: 25000, stdio: ['ignore', 'pipe', 'ignore']});
  } catch (e) { return; }
  for (const line of out.split('\n')) {
    for (const ip of C2_IPS) {
      if (line.indexOf(ip) !== -1) {
        addFinding(t, 'network', 'critical', line.trim().slice(0, 220),
          'live connection to C2 ' + ip, 'kill-process', '');
        break;
      }
    }
  }
}

function scanEnvAndPersistence(t) {
  for (const k of Object.keys(process.env)) {
    const v = process.env[k] || '';
    if ((k === 'NODE_OPTIONS' || k === '_VSCODE_PRODUCT_JSON') && v) {
      addFinding(t, 'env', 'medium', k + '=' + v.slice(0, 160),
        'environment variable the worm manipulates', 'manual', '');
    } else if (C2_IPS.some((ip) => v.indexOf(ip) !== -1)) {
      addFinding(t, 'env', 'critical', k + '=<contains C2 address>', 'C2 address in environment', 'manual', '');
    }
  }
  const rcFiles = ['.zshrc', '.zprofile', '.bashrc', '.bash_profile', '.profile']
    .map((f) => path.join(HOME, f));
  if (IS_MAC) {
    const la = path.join(HOME, 'Library/LaunchAgents');
    try {
      for (const f of fs.readdirSync(la)) if (f.endsWith('.plist')) rcFiles.push(path.join(la, f));
    } catch (e) { /* absent */ }
  }
  for (const p of rcFiles) {
    const txt = readText(p, 2 * 1024 * 1024);
    if (txt === null) continue;
    for (const [needle, why] of [[path.join(HOME, 'node'), 'installs/runs campaign node root'],
                                 [path.join(HOME, 'py'), 'installs/runs campaign python root'],
                                 ['node20', 'campaign node directory'],
                                 ['jsbot', 'campaign process name']]) {
      if (txt.indexOf(needle) !== -1) {
        addFinding(t, 'persistence', 'critical', p, why + ' (' + needle + ')', 'manual', '');
        break;
      }
    }
    for (const ip of C2_IPS) {
      if (txt.indexOf(ip) !== -1) {
        addFinding(t, 'persistence', 'critical', p, 'C2 address ' + ip, 'manual', '');
        break;
      }
    }
  }
}

// ---------------------------------------------------------------------------------------
// removal
// ---------------------------------------------------------------------------------------

// the worm's OWN strip regexes (from its string table) - exact, not guessed
const STRIP_PATTERNS = [
  [/\r?\n?import\s*\{\s*createRequire\s+as\s+__inzCR\s*\}\s*from\s*['"]module['"]\s*;\s*const\s+__inzV\s*=\s*['"][^'"]*['"]\s*;\s*__inzCR\s*\(\s*import\.meta\.url\s*\)\s*\(\s*['"][^'"]+\.inz\.cjs['"]\s*\)\s*;?\s*/g, '\n'],
  [/\r?\n?const\s+__inzV\s*=\s*['"][^'"]*['"]\s*;\s*const\s+__inzRQ\s*=\s*require\s*\(\s*['"][^'"]+\.inz\.cjs['"]\s*\)\s*;?\s*/g, '\n'],
  [/\/\*(?:RS260605|C25061[789]A|C250620A|C260511A|M260630A)\*\//g, ''],
];

function flatten(p) {
  return path.resolve(p).replace(/^[/\\]+/, '').split(path.sep).join('__');
}

function rmrf(p) {
  let st;
  try { st = fs.lstatSync(p); } catch (e) { return; }
  if (st.isDirectory()) {
    for (const e of fs.readdirSync(p)) rmrf(path.join(p, e));
    try { fs.rmdirSync(p); } catch (e) { /* ignore */ }
  } else {
    try { fs.unlinkSync(p); } catch (e) { /* ignore */ }
  }
}

function copyTree(src, dst) {
  const st = fs.lstatSync(src);
  if (st.isDirectory()) {
    if (!fs.existsSync(dst)) fs.mkdirSync(dst, {recursive: true});
    for (const e of fs.readdirSync(src)) copyTree(path.join(src, e), path.join(dst, e));
  } else {
    fs.mkdirSync(path.dirname(dst), {recursive: true});
    fs.copyFileSync(src, dst);
  }
}

function moveTree(src, dst) {
  fs.mkdirSync(path.dirname(dst), {recursive: true});
  try {
    fs.renameSync(src, dst);
  } catch (e) {          // cross-device
    copyTree(src, dst);
    rmrf(src);
  }
}

function quarantine(src, backupRoot, dry, purge) {
  const rel = flatten(src);
  const dst = path.join(backupRoot, rel);
  if (dry) return '[dry-run] quarantine ' + src;
  try {
    if (purge) {
      const st = fs.lstatSync(src);
      if (st.isDirectory()) copyTree(src, dst); else { fs.mkdirSync(path.dirname(dst), {recursive: true}); fs.copyFileSync(src, dst); }
      rmrf(src);
      return 'BACKED UP + DELETED ' + src;
    }
    const moved = dst + '.MOVED';
    moveTree(src, moved);
    return 'QUARANTINED ' + src + ' -> ' + moved;
  } catch (e) {
    return 'FAILED ' + src + ': ' + e.message;
  }
}

function restoreFromOrig(src, backupRoot, dry, purge) {
  const orig = src + '.inz.orig';
  if (!fs.existsSync(orig)) return 'NO .inz.orig for ' + src;
  try {
    if (dry) return '[dry-run] restore ' + src + ' from .inz.orig';
    const rel = flatten(src);
    const dst = path.join(backupRoot, rel);
    fs.mkdirSync(path.dirname(dst), {recursive: true});
    fs.copyFileSync(src, dst);          // keep the infected copy as evidence
    fs.copyFileSync(orig, src);         // put the pristine file back
    if (purge) { try { fs.unlinkSync(orig); } catch (e) {} }
    else moveTree(orig, path.join(backupRoot, rel + '.inz.orig.MOVED'));
    return 'RESTORED ' + src + ' from .inz.orig (infected copy kept at ' + dst + ')';
  } catch (e) {
    return 'FAILED restore ' + src + ': ' + e.message;
  }
}

function nodeCheck(p) {
  if (!['.js', '.cjs', '.mjs'].includes(path.extname(p))) return '';
  try {
    const r = spawnSync('node', ['--check', p], {timeout: 30000, encoding: 'utf8'});
    if (r.error) return '';
    return r.status === 0 ? '  syntax OK (node --check)'
                          : '  !! node --check FAILED: ' + String(r.stderr || '').trim().slice(0, 120) + ' - restore from the quarantine copy';
  } catch (e) { return ''; }
}

function stripInjected(src, backupRoot, dry) {
  const txt = readText(src, 64 * 1024 * 1024);
  if (txt === null) return 'SKIP (unreadable/binary) ' + src;
  let out = txt;
  for (const [rx, rep] of STRIP_PATTERNS) out = out.replace(rx, rep);

  // Appended stage-1 style loader. DANGER: truncating to EOF destroys legitimate code that
  // follows the injection, so only truncate when the tail looks like the minified loader.
  let note = '';
  const m = /(?:^|\n)(?=global\.i\s*=\s*['"][^'"]{1,16}['"]\s*;?\s*global\.j\s*=\s*1)/m.exec(out);
  if (m) {
    const tail = out.slice(m.index + m[0].length);
    if (tail.indexOf('//') === -1 && tail.indexOf('\n\n') === -1) {
      out = out.slice(0, m.index) + '\n';
      note = '  [appended loader truncated to EOF: ' + tail.length + ' bytes]';
    } else {
      note = '  [appended loader prologue found but code follows it - NOT truncated, review manually]';
    }
  }
  if (out === txt) return 'NO CHANGE (no inject pattern matched) ' + src;
  if (dry) return '[dry-run] strip ' + (txt.length - out.length) + ' bytes from ' + src;

  const rel = flatten(src);
  const dst = path.join(backupRoot, rel);
  fs.mkdirSync(path.dirname(dst), {recursive: true});
  fs.copyFileSync(src, dst);
  fs.writeFileSync(src, out);
  const residual = INJECTION_MARKERS.filter((x) => out.indexOf(x) !== -1)
    .concat(STRONG_SIGNATURES.filter(([rx]) => rx.test(out)).map(([, w]) => w));
  const flag = residual.length ? '  !! RESIDUAL RISK: ' + residual.slice(0, 3).join('; ') : '  (clean)';
  return 'STRIPPED ' + (txt.length - out.length) + ' bytes from ' + src + flag + note + nodeCheck(src);
}

// ---------------------------------------------------------------------------------------
// reporting / CLI
// ---------------------------------------------------------------------------------------

const SEV_ORDER = {critical: 0, high: 1, medium: 2, info: 3};

function report(t, args) {
  const real = t.findings.filter((f) => f.severity !== 'info')
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] ||
                    a.kind.localeCompare(b.kind) || a.path.localeCompare(b.path));

  console.log('');
  console.log('inz_scan.js v' + VERSION + '  |  host ' + os.hostname() + '  |  ' +
              (IS_MAC ? 'macOS' : process.platform) + '  |  node ' + process.version +
              '  |  offline, read-only');
  console.log('='.repeat(78));

  if (!real.length) {
    console.log('\n  NO INDICATORS FOUND\n');
    console.log('  This means the markers we know about are absent - not proof the machine is');
    console.log('  clean. If it was ever exposed: rotate credentials anyway, and re-run --deep.');
  } else {
    const crit = real.filter((f) => f.severity === 'critical').length;
    console.log('\n  ' + real.length + ' FINDING(S)  (' + crit + ' critical)\n');
    for (const f of real) {
      console.log('  [' + f.severity.toUpperCase().padEnd(8) + '] ' + f.kind.padEnd(12) + ' ' + f.path);
      console.log('             ' + f.evidence);
      if (f.detail) console.log('             -> ' + f.detail);
    }
    const kinds = {};
    for (const f of real) kinds[f.kind] = (kinds[f.kind] || 0) + 1;
    console.log('\n  summary: ' + Object.keys(kinds).sort().map((k) => k + '=' + kinds[k]).join(', '));
  }
  console.log('\n  next step:  node inz_scan.js remove-all --dry-run   (preview)');
  if (real.length) console.log('              node inz_scan.js remove-all --yes       (quarantine)');

  if (args.json) {
    fs.writeFileSync(args.json, JSON.stringify({
      scanner: 'inz_scan.js', version: VERSION, platform: process.platform,
      host: os.hostname(), node: process.version,
      scanned_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
      findings: t.findings,
    }, null, 2));
    console.log('\n  json written: ' + args.json);
  }
  return real.length ? 1 : 0;
}

function doRemove(t, args) {
  const ts = new Date().toISOString().split('.')[0].replace(/[-:T]/g, '');
  const backupRoot = args.backupDir || path.join(HOME, 'inz-quarantine-' + ts);
  if (!args.dryRun) {
    fs.mkdirSync(backupRoot, {recursive: true});
    console.log('[*] quarantine: ' + backupRoot + (args.purge ? '   (files DELETED after backup: --purge)' : '') + '\n');
  }
  if (!args.yes && !args.dryRun) {
    console.log('[!] This will modify the system. Re-run with --yes to proceed, or --dry-run to preview.');
    return 2;
  }

  const actions = [], reinstalls = [], manual = [], handled = new Set();
  const byPath = new Map();
  for (const f of t.findings) {
    if (f.severity === 'info') continue;
    const cur = byPath.get(f.path);
    if (!cur || f.action === 'restore-orig' || f.action === 'kill-process') byPath.set(f.path, f);
  }
  const paths = Array.from(byPath.keys()).sort();

  // pass 1 - restores first, so .inz.orig is still in place when we use it
  for (const p of paths) {
    const f = byPath.get(p);
    if (f.action !== 'restore-orig' || f.kind !== 'injected') continue;
    if (!fs.existsSync(p)) continue;
    if (fs.existsSync(p + '.inz.orig')) {
      actions.push(restoreFromOrig(p, backupRoot, args.dryRun, args.purge));
      handled.add(p);
      if (fs.existsSync(p + '.inz.cjs')) {
        actions.push(quarantine(p + '.inz.cjs', backupRoot, args.dryRun, args.purge));
        handled.add(p + '.inz.cjs');
      }
      handled.add(p + '.inz.orig');
    } else if (args.strip) {
      actions.push(stripInjected(p, backupRoot, args.dryRun));
      handled.add(p);
    } else {
      reinstalls.push(p); handled.add(p);
    }
  }

  // pass 2 - everything else
  for (const p of paths) {
    if (handled.has(p)) continue;
    const f = byPath.get(p);
    if (f.action === 'kill-process' || f.kind === 'process' || f.kind === 'network') {
      manual.push('investigate live process/socket manually: ' + p); continue;
    }
    if (f.kind === 'env') { manual.push('check and remove this environment variable: ' + p); continue; }
    if (f.kind === 'lockfile') { manual.push('remove the package from ' + p + ' and reinstall from a clean lockfile'); continue; }
    if (f.kind === 'npm-cache') { manual.push('npm cache clean --force   (clear the poisoned cache)'); continue; }
    if (!fs.existsSync(p)) continue;
    if (f.kind === 'injected') {
      if (args.strip) actions.push(stripInjected(p, backupRoot, args.dryRun));
      else reinstalls.push(p);
      continue;
    }
    if (['package', 'staging', 'install-root', 'temp-cache'].indexOf(f.kind) !== -1) {
      actions.push(quarantine(p, backupRoot, args.dryRun, args.purge));
    }
  }

  for (const a of actions) console.log('  ' + a);
  if (reinstalls.length) {
    console.log('\n[!] Injected application files - RESTORE BY REINSTALLING (do not patch vendor binaries):');
    for (const r of reinstalls) {
      if (r.indexOf('npm/lib/cli.js') !== -1 || r.indexOf('npm\\lib\\cli.js') !== -1) console.log('    ' + r + '\n      -> npm i -g npm@latest');
      else if (r.indexOf('Visual Studio Code.app') !== -1) console.log('    ' + r + '\n      -> reinstall VS Code from the official .dmg');
      else if (r.indexOf('Cursor.app') !== -1) console.log('    ' + r + '\n      -> reinstall Cursor from cursor.com');
      else if (r.indexOf('Antigravity.app') !== -1) console.log('    ' + r + '\n      -> reinstall Antigravity from the official installer');
      else if (/discord/i.test(r)) console.log('    ' + r + '\n      -> reinstall Discord.app');
      else if (r.indexOf('GitHub Desktop') !== -1) console.log('    ' + r + '\n      -> reinstall GitHub Desktop');
      else console.log('    ' + r);
    }
    console.log('      then re-run:  node inz_scan.js scan');
  }
  for (const m of manual) console.log('  [manual] ' + m);

  console.log('\n[*] ' + actions.length + ' action(s). ' +
              (args.dryRun ? '(dry run - nothing changed)' : 'Quarantine: ' + backupRoot));
  if (!args.dryRun) console.log('[*] Nothing was deleted' + (args.purge ? ' except after backup (--purge).' : ' - quarantined files can be restored.'));
  return 0;
}

function parseArgs(argv) {
  const args = {cmd: 'scan', roots: [], exclude: [], deep: false, json: null,
                verbose: false, yes: false, dryRun: false, purge: false, strip: false, backupDir: null};
  let i = 0;
  if (argv[0] === 'scan' || argv[0] === 'remove-all') { args.cmd = argv[0]; i = 1; }
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--root') args.roots.push(argv[++i]);
    else if (a === '--exclude') args.exclude.push(argv[++i]);
    else if (a === '--deep') args.deep = true;
    else if (a === '--json') args.json = argv[++i];
    else if (a === '-v' || a === '--verbose') args.verbose = true;
    else if (a === '--yes') args.yes = true;
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--purge') args.purge = true;
    else if (a === '--strip') args.strip = true;
    else if (a === '--backup-dir') args.backupDir = argv[++i];
    else if (a === '-h' || a === '--help') { usage(); process.exit(0); }
    else { console.error('unknown option: ' + a); usage(); process.exit(64); }
  }
  return args;
}

function usage() {
  console.log([
    'inz_scan.js v' + VERSION + ' - detect (and optionally remove) the NullReceiver / "jsbot" developer worm',
    '',
    '  node inz_scan.js scan [options]            read-only detection (default)',
    '  node inz_scan.js remove-all [options]      quarantine everything detected',
    '',
    'options:',
    '  --root DIR        limit scan to DIR (repeatable)',
    '  --exclude DIR     skip DIR (repeatable)',
    '  --deep            grep every JS/TS file, not just the allowlist',
    '  --json FILE       write findings as JSON',
    '  --verbose, -v     show files checked clean',
    '  --dry-run         show what removal would do, change nothing',
    '  --yes             required for remove-all to actually modify the system',
    '  --strip           also neutralise injected code blocks in app files',
    '  --purge           delete instead of quarantine (after backup)',
    '  --backup-dir DIR  quarantine location (default ~/inz-quarantine-<ts>)',
    '',
    'scan is read-only and offline. remove-all quarantines; it never deletes unless --purge.',
    'exit: 0 clean, 1 findings, 2 missing --yes',
  ].join('\n'));
}

function main() {
  const major = parseInt(process.versions.node.split('.')[0], 10);
  const minor = parseInt(process.versions.node.split('.')[1], 10);
  if (major < 14 || (major === 14 && minor < 14)) {
    console.error('inz_scan.js needs Node 14.14+ (found ' + process.version + ')');
    return 64;
  }
  const args = parseArgs(process.argv.slice(2));
  EXCLUDES = args.exclude.map((e) => path.resolve(e));
  const roots = args.roots.length ? args.roots.map((r) => path.resolve(r)) : [HOME];

  process.stderr.write('[*] scanning ' + roots.join(', ') + ' ...\n');
  const t = tracking();
  try { scanTargetFiles(t); } catch (e) { /* keep going */ }
  for (const r of roots) { try { walkRoot(r, args.deep, t); } catch (e) {} }
  try { scanInstallRoots(t); } catch (e) {}
  try { scanNpmCache(t); } catch (e) {}
  try { scanProcesses(t); } catch (e) {}
  try { scanNetwork(t); } catch (e) {}
  try { scanEnvAndPersistence(t); } catch (e) {}

  return args.cmd === 'remove-all' ? doRemove(t, args) : report(t, args);
}

if (require.main === module) process.exit(main());

module.exports = {VERSION, INJECTION_MARKERS, STRONG_SIGNATURES, MALICIOUS_PACKAGES,
                  grepSignatures, stripInjected, origIsPristine, parseArgs,
                  injectionTargets, C2_IPS, INSTALL_ROOTS, STAGING_SUFFIXES, ANTI_ANALYSIS_MD5};
