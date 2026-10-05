#!/usr/bin/env node
'use strict';
/**
 * selftest_macos.js - darwin-only assertions for inz_scan.js
 *
 * WHY THIS EXISTS: a fresh GitHub macOS runner has no VS Code / Cursor / Antigravity / Discord /
 * GitHub Desktop installed, so every macOS-specific path in injection_targets() is skipped and the
 * normal suite proves only that the script runs - not that the macOS detection works.
 *
 * So this plants the macOS paths (fake $HOME for the Library/ paths, real /Applications for the
 * app paths) and asserts the scanner finds them. Cleanup removes everything it creates.
 *
 * Skips cleanly (exit 0) on non-darwin, so it is safe to run anywhere.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const {spawnSync} = require('child_process');
const scanner = require('./inz_scan.js');

if (process.platform !== 'darwin') {
  console.log('SKIP: selftest_macos.js is darwin-only (running on ' + process.platform + ')');
  process.exit(0);
}

const SHIM = "const __inzV='260902';const __inzRQ=require('/Users/dev/x.inz.cjs');\n";
const MARKER = '/*RS260605*/';
const PROLOGUE = "global.i='A11--#';global.j=1;\n";
const PRISTINE = '// pristine vendor file\nmodule.exports = {ok:true};\n';
const INFECTED = '// vendor file\n' + SHIM + 'module.exports = {ok:true};\n' + MARKER + '\n' + PROLOGUE;

const results = [];
function check(name, ok, extra) {
  results.push([name, !!ok]);
  console.log('  [' + (ok ? 'PASS' : 'FAIL') + '] ' + name + (ok || !extra ? '' : '   ' + extra));
}
function skip(name, why) {
  results.push([name, true]);           // skipped != failed
  console.log('  [SKIP] ' + name + '   ' + why);
}

function rmrf(p) {
  try {
    if (fs.lstatSync(p).isDirectory()) {
      for (const e of fs.readdirSync(p)) rmrf(path.join(p, e));
      fs.rmdirSync(p);
    } else fs.unlinkSync(p);
  } catch (e) { /* ignore */ }
}

function run(home, argv) {
  const r = spawnSync('node', [path.join(__dirname, 'inz_scan.js')].concat(argv), {
    encoding: 'utf8', timeout: 600000,
    env: Object.assign({}, process.env, {HOME: home}),
  });
  return {out: (r.stdout || '') + (r.stderr || ''), code: r.status};
}

const APP_MAIN = '/Applications/Visual Studio Code.app/Contents/Resources/app/out/main.js';
const created = [];

function main() {
  console.log('\n=== darwin-only suite (real macOS, node ' + process.version + ') ===\n');

  // ---- 1. platform branching: darwin must return the macOS list, not the Linux one ----
  console.log('--- platform branching ---');
  const mac = scanner.injectionTargets('darwin').map(([p]) => p);
  const lin = scanner.injectionTargets('linux').map(([p]) => p);
  check('darwin target set includes /Applications VS Code main', mac.indexOf(APP_MAIN) !== -1);
  check('darwin target set includes the Library/Application Support Discord path',
    mac.some((p) => p.indexOf('Library/Application Support/discord') !== -1));
  check('darwin target set does NOT include the Linux /usr/share paths',
    !mac.some((p) => p.indexOf('/usr/share/code') === 0));
  check('linux target set does NOT include the macOS /Applications paths',
    !lin.some((p) => p.indexOf('/Applications/') === 0));
  check('the two platform target sets differ', JSON.stringify(mac) !== JSON.stringify(lin));

  // ---- 2. real BSD ps (this is what the -e -> -A fix was for) ----
  console.log('\n--- real BSD ps ---');
  const ps = spawnSync('ps', ['-Ao', 'pid=,args='], {encoding: 'utf8', timeout: 20000});
  check('ps -Ao pid=,args= runs on BSD ps', !ps.error && ps.status === 0,
    ps.error ? ps.error.message : 'status ' + ps.status);
  check('ps -Ao returns a usable process list', (ps.stdout || '').split('\n').filter(Boolean).length > 5);

  // ---- 3. lsof exists ----
  console.log('\n--- lsof ---');
  const lsof = spawnSync('lsof', ['-nP', '-i'], {encoding: 'utf8', timeout: 25000});
  check('lsof -nP -i is present and does not throw', !lsof.error,
    lsof.error ? lsof.error.message : '');

  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'inz-mac-'));

  // ---- 4. /Applications target: infect, detect, restore from .inz.orig ----
  console.log('\n--- /Applications injection target (real path) ---');
  let appOk = true, appWhy = '';
  try {
    fs.mkdirSync(path.dirname(APP_MAIN), {recursive: true});
    created.push(APP_MAIN);
    fs.writeFileSync(APP_MAIN, INFECTED);
    fs.writeFileSync(APP_MAIN + '.inz.orig', PRISTINE);
    created.push(APP_MAIN + '.inz.orig');
  } catch (e) {
    appOk = false; appWhy = e.code || e.message;
  }
  if (!appOk) {
    skip('infect /Applications VS Code main.js', 'not writable without sudo (' + appWhy + ')');
    skip('/Applications target is detected', 'depends on previous');
    skip('/Applications target auto-restores from .inz.orig', 'depends on previous');
  } else {
    let r = run(home, ['scan', '--root', home]);
    check('/Applications target is detected', r.out.indexOf(APP_MAIN) !== -1);
    check('/Applications finding is critical', /CRITICAL.*injected|injected.*VS Code main/.test(r.out));
    r = run(home, ['remove-all', '--yes', '--root', home]);
    check('/Applications target auto-restores from .inz.orig',
      fs.readFileSync(APP_MAIN, 'utf8') === PRISTINE,
      'file is: ' + JSON.stringify(fs.readFileSync(APP_MAIN, 'utf8').slice(0, 60)));
    check('/Applications restore reported as RESTORED', r.out.indexOf('RESTORED') !== -1);
    rmrf(APP_MAIN); rmrf(APP_MAIN + '.inz.orig');
  }

  // ---- 5. Library/Application Support Discord target (fake $HOME) ----
  console.log('\n--- ~/Library/Application Support/discord target ---');
  const discord = path.join(home, 'Library/Application Support/discord/modules/discord_desktop_core/index.js');
  fs.mkdirSync(path.dirname(discord), {recursive: true});
  fs.writeFileSync(discord, INFECTED);
  let r = run(home, ['scan', '--root', home]);
  check('Discord core target is detected on darwin', r.out.indexOf(discord) !== -1);
  check('Discord finding recommends reinstall (no .inz.orig present)',
    r.out.indexOf('reinstall') !== -1);

  // ---- 6. launchd persistence ----
  console.log('\n--- ~/Library/LaunchAgents persistence ---');
  const la = path.join(home, 'Library/LaunchAgents');
  fs.mkdirSync(la, {recursive: true});
  fs.writeFileSync(path.join(la, 'com.example.inz.plist'),
    '<?xml version="1.0"?><plist><dict><string>' + path.join(home, 'node', 'index.js') + '</string></dict></plist>\n');
  r = run(home, ['scan', '--root', home]);
  check('launchd plist referencing ~/node is detected',
    r.out.indexOf('com.example.inz.plist') !== -1 && r.out.indexOf('persistence') !== -1);

  // ---- 7. macOS install roots ----
  console.log('\n--- install roots on darwin ---');
  fs.mkdirSync(path.join(home, 'py', '.local', 'bin'), {recursive: true});
  fs.writeFileSync(path.join(home, 'py', '.local', 'bin', 'python3'), '#!sh\n');
  r = run(home, ['scan', '--root', home]);
  check('~/py install root detected on darwin', r.out.indexOf(path.join(home, 'py')) !== -1);

  rmrf(home);
  for (const p of created) rmrf(p);

  const passed = results.filter(([, ok]) => ok).length;
  console.log('\n' + '='.repeat(66));
  console.log('  ' + passed + '/' + results.length + ' darwin checks passed');
  const failed = results.filter(([, ok]) => !ok).map(([n]) => n);
  if (failed.length) console.log('  FAILED: ' + failed.join('; '));
  return failed.length ? 1 : 0;
}

process.exit(main());
