#!/usr/bin/env node
// Dashboard i18n JS smoke test (CI: .github/workflows/go-test.yml).
//
// Executes the real <head> inline scripts that Go embeds in the admin panel —
// the static boot script (t/tf/__norm) plus, on the zh variant, the zhBoot
// dict — and asserts the JS actually runs, the zh dict installs and resolves,
// and no JS/comment text leaks into the visible page. The latter is the exact
// regression where a literal "</head>" inside a JS comment made lang.go init()
// inject zhBoot into the middle of the comment, whose own </script> prematurely
// closed the outer script and the remaining boot source rendered as "乱码".
//
// Requires the en/zh variants dumped by the sibling Go test
// internal/admin/dashboard_dump_test.go (see DASHBOARD_DUMP_DIR there).
//
// Usage: node dashboard-i18n.test.js <dump-dir>
//   dump-dir defaults to $DASHBOARD_DUMP_DIR, then ./.ci-i18n.
// Conservative ES2018: also runs on repo's old Node 12.

'use strict';
const fs = require('fs');
const path = require('path');

const dir = process.argv[2] || process.env.DASHBOARD_DUMP_DIR || './.ci-i18n';
function read(p) { return fs.readFileSync(p, 'utf8'); }
const en = read(path.join(dir, 'dashboard-en.html'));
const zh = read(path.join(dir, 'dashboard-zh.html'));

let fails = 0;
function check(name, cond, extra) {
  if (cond) { console.log('PASS ' + name); }
  else { fails++; console.log('FAIL ' + name + (extra !== undefined ? '  [' + extra + ']' : '')); }
}

// ── 1. structure ──────────────────────────────────────────────
check('en single literal </head>', (en.match(/<\/head>/g) || []).length === 1);
check('zh single literal </head>', (zh.match(/<\/head>/g) || []).length === 1);
const b = zh.indexOf("window.SP_LANG='zh'");
const h = zh.indexOf('</head>');
const by = zh.indexOf('<body');
check('zh order boot < </head> < <body', b >= 0 && h >= 0 && by >= 0 && b < h && h < by, 'b=' + b + ' h=' + h + ' body=' + by);
function openSc(s) { return (s.match(/<script/g) || []).length; }
function closeSc(s) { return (s.match(/<\/script/g) || []).length; }
check('en script tags paired', openSc(en) === closeSc(en), openSc(en) + '/' + closeSc(en));
check('zh script tags paired', openSc(zh) === closeSc(zh), openSc(zh) + '/' + closeSc(zh));

// ── 2. no JS/comment text leaking into the visible page ──────
function visible(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<title>[\s\S]*?<\/title>/gi, ' ')
    .replace(/<[^>]*>/g, ' ');
}
const visEn = visible(en);
const visZh = visible(zh);
['i18n boot', 'window.SP_LANG=', 'zh launcher', '__norm', 'SP_I18N', 'function t('].forEach(function (probe) {
  check('en no text leak: ' + probe, !visEn.includes(probe));
  check('zh no text leak: ' + probe, !visZh.includes(probe));
});

// ── 3. execute the real head inline scripts ──────────────────
function headInlineScripts(html) {
  const head = html.slice(0, html.indexOf('<body'));
  const out = [];
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(head)) !== null) out.push(m[1]);
  return out.join('\n');
}
function norm(s) { return String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); }

// zh: boot defines t()/tf(); zhBoot then installs dict + SP_LANG='zh'.
global.window = globalThis;
const zhCode = headInlineScripts(zh);
try { (0, eval)(zhCode); }
catch (e) { check('zh head scripts execute', false, e && e.message); process.exit(fails ? 1 : 0); }
check('zh SP_LANG === zh', window.SP_LANG === 'zh', window.SP_LANG);
check('zh t() defined', typeof window.t === 'function');
check('zh tf() defined', typeof window.tf === 'function');
const dict = window.SP_I18N;
const dk = dict && Object.keys(dict).length;
check('zh SP_I18N dict installed (>100 keys)', dk > 100, String(dk));
check('zh SP_I18N_PRE arrays aligned', Array.isArray(window.SP_I18N_PRE.k) && window.SP_I18N_PRE.k.length === window.SP_I18N_PRE.v.length && window.SP_I18N_PRE.k.length > 0, window.SP_I18N_PRE && window.SP_I18N_PRE.k.length);
check('zh SP_I18N_HTML dict installed', window.SP_I18N_HTML && Object.keys(window.SP_I18N_HTML).length > 0);

// every plain (non-template) key must resolve to exactly its zh value
let bad = 0, collisions = 0, identityVals = 0; const seen = {};
for (const k of Object.keys(dict)) {
  if (k.indexOf('{') >= 0) continue;            // template → tf() only
  const n = norm(k);
  if (seen[n] !== undefined) {
    collisions++;
    if (seen[n] !== k) console.log('    norm collision: ' + JSON.stringify(k) + ' vs ' + JSON.stringify(seen[n]));
  }
  seen[n] = k;
  const got = window.t(k);
  if (got !== dict[k]) { bad++; console.log('    t(' + JSON.stringify(k) + ') = ' + JSON.stringify(got) + ' want ' + JSON.stringify(dict[k])); }
  if (dict[k] === k) identityVals++;           // legit: zh value is the English text itself
}
check('zh t() returns dict value for every plain key', bad === 0, bad + ' bad / ' + Object.keys(dict).length);
check('zh normalised-key collision: none', collisions === 0);
console.log('INFO ' + identityVals + ' plain keys keep English text (identity zh value, expected)');

// pick a template whose zh text keeps BOTH placeholders, then tf() must fill them
let tpl = null;
for (const k of Object.keys(dict)) {
  if (k.indexOf('{0}') >= 0 && k.indexOf('{1}') >= 0 && dict[k].indexOf('{0}') >= 0 && dict[k].indexOf('{1}') >= 0) { tpl = k; break; }
}
if (tpl) {
  const got = window.tf(tpl, ['X', 'Y']);
  check('zh tf() substitutes {0} and {1}', typeof got === 'string' && got.indexOf('X') >= 0 && got.indexOf('Y') >= 0, JSON.stringify(got));
} else check('zh two-placeholder template present', false);

// en: fresh, identity behaviour — must stay English, no dict.
global.SP_LANG = undefined; global.SP_I18N = undefined; global.SP_I18N_PRE = undefined; global.SP_I18N_HTML = undefined;
const enCode = headInlineScripts(en);
try { (0, eval)(enCode); }
catch (e) { check('en head scripts execute', false, e && e.message); }
check('en SP_LANG defaults to en', window.SP_LANG === 'en', window.SP_LANG);
check('en no dict + t() is identity', window.SP_I18N === undefined && window.t('Overview') === 'Overview');

console.log(fails ? ('\n' + fails + ' FAILURE(S)') : '\nALL PASS');
process.exit(fails ? 1 : 0);
