#!/usr/bin/env node
'use strict';
/**
 * selftest_inz_scan.js - regression suite for inz_scan.js
 *
 * Builds synthetic infected fixtures in a throwaway tree, runs the scanner against them, and
 * asserts both DETECTION and REMOVAL behaviour (including the safety cases that matter:
 * benign code must never be destroyed, and dry-run must change nothing).
 *
 *   node selftest_inz_scan.js [path/to/inz_scan.js]
 *
 * Exit code 0 = all pass.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const {spawnSync} = require('child_process');

const SCANNER = path.resolve(process.argv[2] || path.join(__dirname, 'inz_scan.js'));
const PRISTINE = "// npm cli - pristine\nmodule.exports = function cli(){ return 'clean'; };\n";
const MARKER = '/*RS260605*/';
const SHIM = "const __inzV='260902';const __inzRQ=require('/Users/dev/inz/x.inz.cjs');\n";
const PROLOGUE = "global.i='A11--#';global.j=1;global['e']='QQ==';\n";

const results = [];
function check(name, ok, extra) {
  results.push([name, !!ok]);
  console.log('  [' + (ok ? 'PASS' : 'FAIL') + '] ' + name + (ok || !extra ? '' : '   ' + extra));
}

function rmrf(p) {
  try {
    if (fs.lstatSync(p).isDirectory()) {
      for (const e of fs.readdirSync(p)) rmrf(path.join(p, e));
      fs.rmdirSync(p);
    } else fs.unlinkSync(p);
  } catch (e) { /* ignore */ }
}

function build(base) {
  const home = path.join(base, 'home'), proj = path.join(base, 'proj');
  fs.mkdirSync(path.join(home, 'node'), {recursive: true});
  fs.writeFileSync(path.join(home, 'node', 'index.js'), '// backdoor\n');
  fs.mkdirSync(path.join(home, 'py', '.local', 'bin'), {recursive: true});
  fs.writeFileSync(path.join(home, 'py', '.local', 'bin', 'python3'), '#!sh\n');
  fs.writeFileSync(path.join(home, '.zshrc'), 'export PATH="$HOME/node:$PATH"\n');
  const cache = path.join(home, '.npm', '_cacache', 'index-v5', 'ab', 'cd');
  fs.mkdirSync(cache, {recursive: true});
  fs.writeFileSync(path.join(cache, 'x'), 'tailwindcss-motion-advanced-1.0.1.tgz');

  const pkg = path.join(proj, 'node_modules', 'tailwindcss-motion-advanced');
  fs.mkdirSync(pkg, {recursive: true});
  fs.writeFileSync(path.join(pkg, 'package.json'),
    JSON.stringify({name: 'tailwindcss-motion-advanced', version: '1.0.1'}));

  const lib = path.join(proj, 'node_modules', 'npm', 'lib');
  fs.mkdirSync(lib, {recursive: true});
  fs.writeFileSync(path.join(lib, 'cli.js'),
    "// npm cli\n" + SHIM + "module.exports=function cli(){return 'clean';};\n" + MARKER + '\n' + PROLOGUE);
  fs.writeFileSync(path.join(lib, 'cli.js.inz.orig'), PRISTINE);
  fs.writeFileSync(path.join(lib, 'cli.js.inz.cjs'), '/* staged */\n');

  // benign control - must never be flagged
  fs.writeFileSync(path.join(proj, 'app.js'),
    "const x=require('http');\nconst msecs=0xe1f0; // common minified constant\n" +
    "/* route names */ global.i='v1'; global.j=2;\n");
  fs.writeFileSync(path.join(proj, 'package-lock.json'),
    JSON.stringify({packages: {'node_modules/tailwindcss-motion-advanced': {version: '1.0.1'}}}));
  return {home, proj};
}

function run(home, argv) {
  const r = spawnSync('node', [SCANNER].concat(argv), {
    encoding: 'utf8', timeout: 600000, env: Object.assign({}, process.env, {HOME: home}),
  });
  return {out: (r.stdout || '') + (r.stderr || ''), code: r.status};
}

function main() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'inz-selftest-'));
  try {
    const {home, proj} = build(base);
    const tmpcache = '/tmp/nm-npm-cache-selftest';
    rmrf(tmpcache);
    fs.mkdirSync(tmpcache, {recursive: true});
    fs.writeFileSync(path.join(tmpcache, 'package.json'), '{"name":"c"}');

    console.log('\n--- detection ---');
    let r = run(home, ['scan', '--root', proj]);
    const wants = [
      ['injected npm CLI detected', 'node_modules/npm/lib/cli.js'],
      ['staging artefact detected', 'cli.js.inz.cjs'],
      ['malicious package detected', 'tailwindcss-motion-advanced'],
      ['install root detected', '/node'],
      ['npm cache exposure detected', '_cacache'],
      ['lockfile exposure detected', 'package-lock.json'],
      ['temp install cache detected', 'nm-npm-cache-selftest'],
    ];
    for (const [name, needle] of wants) check(name, r.out.indexOf(needle) !== -1);
    check('benign control file NOT flagged', r.out.indexOf(path.join(proj, 'app.js')) === -1);
    check('exit code 1 when findings exist', r.code === 1, 'got ' + r.code);
    check('dry-run offered in output', r.out.indexOf('remove-all --dry-run') !== -1);

    console.log('\n--- read-only guarantee ---');
    const cli = path.join(proj, 'node_modules', 'npm', 'lib', 'cli.js');
    const before = fs.readFileSync(cli, 'utf8');
    run(home, ['remove-all', '--dry-run', '--root', proj]);
    check('dry-run does not modify the infected file', fs.readFileSync(cli, 'utf8') === before);
    check('dry-run leaves .inz.orig in place', fs.existsSync(cli + '.inz.orig'));

    console.log('\n--- removal ---');
    r = run(home, ['remove-all', '--yes', '--root', proj]);
    check('cli.js restored byte-exact from .inz.orig', fs.readFileSync(cli, 'utf8') === PRISTINE);
    const after = fs.readFileSync(cli, 'utf8');
    check('restored file is marker-free',
      [MARKER, 'global.j=1', '__inzRQ', '__inzV='].every((m) => after.indexOf(m) === -1));
    check('staging .inz.cjs quarantined', !fs.existsSync(cli + '.inz.cjs'));
    check('malicious package quarantined', !fs.existsSync(path.join(proj, 'node_modules', 'tailwindcss-motion-advanced')));
    check('~/node install root quarantined', !fs.existsSync(path.join(home, 'node')));
    check('~/py install root quarantined', !fs.existsSync(path.join(home, 'py')));
    check('/tmp install cache quarantined', !fs.existsSync(tmpcache));
    check('benign control file untouched', fs.existsSync(path.join(proj, 'app.js')));
    check('lockfile left for manual fix', fs.existsSync(path.join(proj, 'package-lock.json')));

    const qbs = fs.readdirSync(home).filter((f) => f.indexOf('inz-quarantine-') === 0);
    check('quarantine dir created', qbs.length === 1, 'found ' + qbs.length);
    let evidence = false;
    if (qbs.length) {
      const walk = (d) => {
        for (const e of fs.readdirSync(d)) {
          const p = path.join(d, e);
          if (fs.statSync(p).isDirectory()) walk(p);
          if (path.basename(p).endsWith('cli.js')) evidence = true;
        }
      };
      walk(path.join(home, qbs[0]));
    }
    check('infected copy preserved as evidence', evidence);

    console.log('\n--- strip safety ---');
    const stripdir = path.join(base, 'strip');
    fs.mkdirSync(stripdir, {recursive: true});
    const a = path.join(stripdir, 'legit_after.js');
    fs.writeFileSync(a, 'function util(){return 1;}\n' + SHIM + 'module.exports=util;\n' + MARKER + '\n' +
      PROLOGUE + '// real app code after\nmodule.exports.extra=2;\n');
    const b = path.join(stripdir, 'hijacked.min.js');
    fs.writeFileSync(b, 'function plugin(){return "legit"};\n' +
      "global.i='A11--#';global.j=1;const http=require('node:http');(function(){var a=1;})();\n");
    const c = path.join(stripdir, 'from_zero.js');
    fs.writeFileSync(c, PROLOGUE.replace('\n', '') + "const http=require('node:http');\n");

    run(home, ['remove-all', '--yes', '--strip', '--root', stripdir]);
    const ta = fs.readFileSync(a, 'utf8'), tb = fs.readFileSync(b, 'utf8'), tc = fs.readFileSync(c, 'utf8');
    check('A: legit code after injection preserved',
      ta.indexOf('module.exports.extra=2;') !== -1 && ta.indexOf('// real app code after') !== -1);
    check('A: shim removed from file', ta.indexOf('__inzRQ') === -1 && ta.indexOf('__inzV=') === -1);
    check('A: residual prologue flagged, not silently deleted', ta.indexOf('global.j=1') !== -1);
    check('B: appended loader removed', tb.indexOf("require('node:http')") === -1 && tb.indexOf('global.j=1') === -1);
    check('B: legit function preserved', tb.indexOf('function plugin()') !== -1);
    check('C: byte-0 loader removed', tc.indexOf('global.j=1') === -1 && tc.length < 200);
    for (const [label, f] of [['legit_after.js', a], ['hijacked.min.js', b]]) {
      const res = spawnSync('node', ['--check', f], {encoding: 'utf8'});
      check(label + ': still valid JS after strip', !res.error && res.status === 0);
    }

    console.log('\n--- npm CLI target (the worm\'s propagation engine) ---');
    // This box may have no global npm install at all, so build one under a fake $HOME via the
    // nvm path - that exercises the same discovery branch a real user's machine hits.
    const nvmHome = path.join(base, 'nvmhome');
    const nvmRoot = path.join(nvmHome, '.nvm', 'versions', 'node', 'v20.0.0', 'lib', 'node_modules');
    const npmCli = path.join(nvmRoot, 'npm', 'lib', 'cli.js');
    fs.mkdirSync(path.dirname(npmCli), {recursive: true});
    fs.writeFileSync(npmCli, '// clean npm cli\nmodule.exports={};\n');
    fs.writeFileSync(npmCli + '.inz.orig', '// clean npm cli\nmodule.exports={};\n');
    fs.writeFileSync(npmCli,
      "// npm cli\n" + SHIM + MARKER + '\n' + PROLOGUE);

    let nr = run(nvmHome, ['scan', '--root', nvmHome]);
    check('infected npm CLI detected (nvm-discovered root)',
      nr.out.indexOf(npmCli) !== -1 && nr.out.indexOf('[npm CLI]') !== -1);
    nr = run(nvmHome, ['remove-all', '--yes', '--root', nvmHome]);
    check('npm CLI restored byte-exact from its .inz.orig',
      fs.readFileSync(npmCli, 'utf8') === '// clean npm cli\nmodule.exports={};\n');
    check('npm CLI is clean afterwards',
      ['__inzRQ', 'global.j=1', MARKER].every((m) => fs.readFileSync(npmCli, 'utf8').indexOf(m) === -1));

    console.log('\n--- option handling ---');
    r = run(home, ['remove-all', '--root', proj]);
    check('remove-all without --yes exits 2 and changes nothing',
      r.code === 2 && r.out.indexOf('Re-run with --yes') !== -1, 'got ' + r.code);

    // ---- platform branching: verifiable without a Mac, so do it here ----
    console.log('\n--- platform branching (darwin logic asserted on this platform) ---');
    const scanner = require(path.join(__dirname, 'inz_scan.js'));
    const mac = scanner.injectionTargets('darwin').map((x) => x[0]);
    const lin = scanner.injectionTargets('linux').map((x) => x[0]);
    const win = scanner.injectionTargets('win32').map((x) => x[0]);
    check('darwin set contains the /Applications VS Code main.js target',
      mac.indexOf('/Applications/Visual Studio Code.app/Contents/Resources/app/out/main.js') !== -1);
    check('darwin set contains all 8 fixed macOS paths',
      mac.filter((p) => p.indexOf('/Applications/') === 0 ||
                        p.indexOf('Library/Application Support/discord') !== -1).length === 8,
      'got ' + mac.length + ' total');
    check('darwin set has NO Linux /usr/share paths',
      !mac.some((p) => p.indexOf('/usr/share/') === 0));
    check('linux set has NO /Applications paths',
      !lin.some((p) => p.indexOf('/Applications/') === 0));
    check('darwin and linux target sets differ',
      JSON.stringify(mac) !== JSON.stringify(lin));
    // The npm-root entries come from the real filesystem, so they must be IDENTICAL across
    // simulated platforms - only the fixed application-path block switches on platform.
    // Accept either the raw [path, label] pairs from injectionTargets() or plain path strings.
    const npmOf = (s) => s.map((x) => (Array.isArray(x) ? x[0] : x))
                          .filter((p) => p.indexOf('npm' + path.sep + 'lib') !== -1 ||
                                         p.indexOf('npm\\lib') !== -1).sort();
    check('npm-root targets are platform-independent (real FS, both simulated sets agree)',
      JSON.stringify(npmOf(mac)) === JSON.stringify(npmOf(lin)));
    // Ask the scanner what it actually discovered rather than re-deriving it here - duplicated
    // logic is how the previous version of this check managed to pass while proving nothing.
    const discoveredRoots = scanner.globalNpmRoots();
    if (discoveredRoots.length > 0) {
      const targets = scanner.injectionTargets();
      if (npmOf(targets).length === 0) {
        console.log('    DIAG: globalNpmRoots() => ' + JSON.stringify(discoveredRoots));
        console.log('    DIAG: injectionTargets() length ' + targets.length + ', npmOf 0');
        console.log('    DIAG: HOME=' + os.homedir() + '  platform=' + process.platform);
      }
      check('every discovered npm root yields an npm CLI target',
        npmOf(targets).length === discoveredRoots.length,
        'roots=' + discoveredRoots.length + ' targets=' + npmOf(targets).length);
    } else {
      console.log('  [SKIP] no global npm install on this machine (globalNpmRoots() empty)' +
                  ' - npm-CLI target assertion not applicable here');
    }
  } finally {
    rmrf(base);
  }

  const passed = results.filter(([, ok]) => ok).length;
  console.log('\n' + '='.repeat(66));
  console.log('  ' + passed + '/' + results.length + ' checks passed');
  const failed = results.filter(([, ok]) => !ok).map(([n]) => n);
  if (failed.length) console.log('  FAILED: ' + failed.join('; '));
  return failed.length ? 1 : 0;
}

process.exit(main());
