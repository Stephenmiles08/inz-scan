#!/usr/bin/env node
'use strict';
/**
 * parity_check.js - do the Node and Python builds report the SAME findings on the same fixture?
 *
 * Builds one synthetic infected tree, runs both scanners over it with the same fake $HOME,
 * and diffs the (kind, path, severity) sets. Environment-derived findings (process, network,
 * env) are excluded - those legitimately differ per interpreter and per host.
 *
 *   node parity_check.js
 * exit 0 = identical finding sets.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const {spawnSync} = require('child_process');

const DIR = __dirname;
const ENV_DEPENDENT = new Set(['process', 'network', 'env']);

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
  fs.mkdirSync(path.join(home, 'node20'), {recursive: true});
  fs.writeFileSync(path.join(home, '.zshrc'), 'export PATH="$HOME/node:$PATH"\n');
  fs.writeFileSync(path.join(home, '.bash_profile'), 'export NODE_OPTIONS=--max-old-space-size=4096\n');
  const cache = path.join(home, '.npm', '_cacache', 'index-v5', 'ab', 'cd');
  fs.mkdirSync(cache, {recursive: true});
  fs.writeFileSync(path.join(cache, 'x'), 'tailwindcss-motion-advanced-1.0.1.tgz');

  for (const pkg of ['tailwindcss-motion-advanced', 'agentgui', 'fluid-type-ui']) {
    const d = path.join(proj, 'node_modules', pkg);
    fs.mkdirSync(d, {recursive: true});
    fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({name: pkg, version: '1.0.1'}));
  }
  const lib = path.join(proj, 'node_modules', 'npm', 'lib');
  fs.mkdirSync(lib, {recursive: true});
  fs.writeFileSync(path.join(lib, 'cli.js'),
    "// npm cli\nconst __inzV='260902';const __inzRQ=require('/Users/dev/x.inz.cjs');\n" +
    "module.exports=function cli(){return 'clean';};\n/*RS260605*/\nglobal.i='A11--#';global.j=1;global['e']='QQ==';\n");
  fs.writeFileSync(path.join(lib, 'cli.js.inz.orig'), '// pristine\n');
  fs.writeFileSync(path.join(lib, 'cli.js.inz.cjs'), '/* staged */\n');
  fs.writeFileSync(path.join(lib, 'cli.js.inz.tmp'), '/* tmp */\n');
  fs.writeFileSync(path.join(proj, 'package-lock.json'),
    JSON.stringify({packages: {'node_modules/tailwindcss-motion-advanced': {version: '1.0.1'}}}));
  // a file carrying the anti-analysis digest + a C2 address, outside node_modules
  fs.writeFileSync(path.join(proj, 'notes.js'), "// 9a47bb48b7b8ca41fc138fd3372e8cc0 91.218.183.174\n");
  // benign control
  fs.writeFileSync(path.join(proj, 'app.js'), "const x=require('http');\n/* r */ global.i='v1'; global.j=2;\n");
  return {home, proj};
}

function runScanner(cmd, argv, home) {
  const r = spawnSync(cmd, argv, {
    encoding: 'utf8', timeout: 600000,
    env: Object.assign({}, process.env, {HOME: home}),
  });
  if (r.error) { console.error('failed to run ' + cmd + ': ' + r.error.message); process.exit(2); }
  return r;
}

function normalise(json) {
  const set = new Set();
  for (const f of json.findings) {
    if (ENV_DEPENDENT.has(f.kind)) continue;
    set.add(f.kind + ' | ' + path.resolve(f.path) + ' | ' + f.severity);
  }
  return set;
}

function main() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'inz-parity-'));
  try {
    const {home, proj} = build(base);
    const pyJson = path.join(base, 'py.json'), jsJson = path.join(base, 'js.json');

    runScanner('python3', [path.join(DIR, 'inz_scan.py'), 'scan', '--root', proj, '--root', home, '--json', pyJson], home);
    runScanner('node', [path.join(DIR, 'inz_scan.js'), 'scan', '--root', proj, '--root', home, '--json', jsJson], home);

    const py = normalise(JSON.parse(fs.readFileSync(pyJson, 'utf8')));
    const js = normalise(JSON.parse(fs.readFileSync(jsJson, 'utf8')));

    const onlyPy = [...py].filter((x) => !js.has(x)).sort();
    const onlyJs = [...js].filter((x) => !py.has(x)).sort();

    console.log('python findings (env-independent): ' + py.size);
    console.log('node   findings (env-independent): ' + js.size);
    console.log('in common                        : ' + [...py].filter((x) => js.has(x)).length);
    if (onlyPy.length) { console.log('\nONLY IN PYTHON:'); for (const x of onlyPy) console.log('  ' + x); }
    if (onlyJs.length) { console.log('\nONLY IN NODE:');   for (const x of onlyJs) console.log('  ' + x); }

    const same = onlyPy.length === 0 && onlyJs.length === 0 && py.size > 0;
    console.log('\n' + (same ? 'PARITY OK - identical finding sets (' + py.size + ' findings)'
                             : 'PARITY MISMATCH'));
    return same ? 0 : 1;
  } finally {
    rmrf(base);
  }
}

process.exit(main());
