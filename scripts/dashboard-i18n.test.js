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

// ── 3b. zh runtime relabels stay Chinese ─────────────────────
// The zh launcher's MutationObserver used to recurse only ELEMENT addedNodes, so a
// bare text node — exactly what `el.textContent='…'` replace-all appends — was
// never translated. Result: runtime relabels leaked English in zh ('paused'/'auto'
// toggles, busy-state buttons, 'Error: '+msg prefix concats). Re-run the REAL
// launcher + REAL toggle functions against a stub DOM and assert the labels come
// out Chinese (the 'paused'/'auto' regression the user hit).
(function () {
  const lm = zh.indexOf('/* zh launcher:');
  const le = zh.lastIndexOf('})();');
  if (lm < 0 || le < 0 || le <= lm) { check('zh launcher found in body', false); return; }
  const launcherSrc = zh.slice(lm, le + '})();'.length);

  const observers = [];
  function dispatch(records) { for (let i = 0; i < observers.length; i++) observers[i](records); }
  function MiniMO(cb) { this.cb = cb; }
  MiniMO.prototype.observe = function () { observers.push(this.cb); };
  global.MutationObserver = MiniMO;

  function mkEl(id) {
    const e = {
      nodeType: 1, id: id || '', childNodes: [], attributes: {}, parentElement: null,
      classList: (function () { const s = new Set(); return {
        add(c) { s.add(c); }, remove(c) { s.delete(c); }, toggle(c) { s.has(c) ? s.delete(c) : s.add(c); },
        contains(c) { return s.has(c); } }; })(),
      getAttribute(n) { return n in this.attributes ? this.attributes[n] : null; },
      setAttribute(n, v) { this.attributes[n] = String(v); dispatch([{ type: 'attributes', target: this }]); },
      removeAttribute(n) { delete this.attributes[n]; },
      closest() { return null; },
    };
    Object.defineProperty(e, 'textContent', {
      get() { return e.childNodes.map(function (c) { return c.nodeValue == null ? '' : c.nodeValue; }).join(''); },
      set(v) {
        const removed = e.childNodes.slice();
        const tn = { nodeType: 3, nodeValue: String(v), parentElement: e };
        e.childNodes = [tn];
        dispatch([{ type: 'childList', addedNodes: [tn], removedNodes: removed }]);
      },
    });
    return e;
  }
  const reg = {};
  const body = mkEl('body');
  function addEl(id, staticText) {
    const e = mkEl(id); reg[id] = e; e.parentElement = body; body.childNodes.push(e);
    if (staticText != null) { e.childNodes = [{ nodeType: 3, nodeValue: staticText, parentElement: e }]; }
    return e;
  }
  // buttons relabelled at runtime, plus an empty status span for the prefix path.
  addEl('bl-auto-btn', 'Auto');
  addEl('traffic-auto-btn', 'Auto');
  addEl('cache-auto-btn', 'Auto');
  addEl('logs-auto-btn', 'Auto Refresh');
  addEl('logs-scroll-btn', 'Auto-scroll: ON');
  addEl('cache-time', '');
  global.document = {
    body: body,
    getElementById(id) { return reg[id] || null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    createElement(tag) { return mkEl(tag); },
  };

  // real launcher first (translates the static initial labels, installs observer)
  try { (0, eval)(launcherSrc); }
  catch (e) { check('zh launcher executes in DOM', false, e && e.message); return; }
  function fnSrc(name) {
    const start = zh.indexOf('function ' + name + '(');
    if (start < 0) return '';
    let i = zh.indexOf('{', start), depth = 0;
    for (; i < zh.length; i++) {
      if (zh[i] === '{') depth++;
      else if (zh[i] === '}') { depth--; if (depth === 0) break; }
    }
    return zh.slice(start, i + 1);
  }
  ['toggleBLAuto', 'toggleTrafficAuto', 'toggleCacheAuto', 'toggleLogsAuto', 'toggleLogsAutoScroll', 'updateLogsScrollBtn'].forEach(function (f) {
    const src = fnSrc(f);
    if (!src) { check('zh fn ' + f + ' found', false); return; }
    try { (0, eval)(src); } catch (e) { check('zh eval ' + f, false, e && e.message); }
  });
  const txt = function (id) { const el = document.getElementById(id); return el ? el.textContent : '(missing)'; };

  // launcher translated the STATIC initial labels at load
  check('zh static bl-auto label', txt('bl-auto-btn') === '自动', txt('bl-auto-btn'));
  check('zh static logs-auto label', txt('logs-auto-btn') === '自动刷新', txt('logs-auto-btn'));
  check('zh static logs-scroll label', txt('logs-scroll-btn') === '自动滚动：开', txt('logs-scroll-btn'));

  // runtime toggles flip to Chinese — the exact 'paused'/'auto' regression
  window.blAuto = true; window.trafficAuto = true; window.cacheAuto = true;
  window.logsAuto = true; window.logsAutoScroll = true;
  toggleBLAuto(); check('zh bl toggle off', txt('bl-auto-btn') === '已暂停', txt('bl-auto-btn'));
  toggleBLAuto(); check('zh bl toggle on', txt('bl-auto-btn') === '自动', txt('bl-auto-btn'));
  toggleTrafficAuto(); check('zh traffic toggle off', txt('traffic-auto-btn') === '已暂停', txt('traffic-auto-btn'));
  toggleCacheAuto(); check('zh cache toggle off', txt('cache-auto-btn') === '已暂停', txt('cache-auto-btn'));
  toggleLogsAuto(); check('zh logs toggle off', txt('logs-auto-btn') === '已暂停', txt('logs-auto-btn'));
  toggleLogsAuto(); check('zh logs toggle on', txt('logs-auto-btn') === '自动刷新', txt('logs-auto-btn'));
  toggleLogsAutoScroll(); check('zh autoscroll off', txt('logs-scroll-btn') === '自动滚动：关', txt('logs-scroll-btn'));
  toggleLogsAutoScroll(); check('zh autoscroll on', txt('logs-scroll-btn') === '自动滚动：开', txt('logs-scroll-btn'));

  // prefix path: a RAW 'Error: '+msg relabel (no t()) must still come out Chinese —
  // the observer now routes bare added text nodes through trText + SP_I18N_PRE.
  document.getElementById('cache-time').textContent = 'Error: boom';
  check('zh raw prefix relabel translated', txt('cache-time') === '错误：boom', txt('cache-time'));

  delete global.MutationObserver;
  delete global.document;
})();

// en: fresh, identity behaviour — must stay English, no dict.
global.SP_LANG = undefined; global.SP_I18N = undefined; global.SP_I18N_PRE = undefined; global.SP_I18N_HTML = undefined;
const enCode = headInlineScripts(en);
try { (0, eval)(enCode); }
catch (e) { check('en head scripts execute', false, e && e.message); }
check('en SP_LANG defaults to en', window.SP_LANG === 'en', window.SP_LANG);
check('en no dict + t() is identity', window.SP_I18N === undefined && window.t('Overview') === 'Overview');

// ── 4. i18n param-shadowing regression ───────────────────
// A function whose parameter is named `t` shadows the global translation
// function t(); if its body then calls t('...') it throws at runtime and the
// whole view goes blank (seen in rbl: param `t` + t('All') → "t is not a
// function" whenever the blacklist had entries). Scan en+zh scripts for any
// function whose param list includes `t` and whose body calls t(...).
function paramTShadow(html) {
  const re = /function\s+([A-Za-z_$][\w$]*)?\s*\(([^)]*)\)\s*\{/g;
  const bad = [];
  let m;
  while ((m = re.exec(html)) !== null) {
    const params = m[2].split(',').map(function (s) { return s.trim(); });
    if (params.indexOf('t') < 0) continue;
    let i = m.index + m[0].length - 1; // points at the opening '{'
    let depth = 0;
    for (; i < html.length; i++) {
      if (html[i] === '{') depth++;
      else if (html[i] === '}') { depth--; if (depth === 0) break; }
    }
    const body = html.slice(m.index + m[0].length, i);
    if (/\bt\s*\(/.test(body)) bad.push((m[1] || '<anon>') + '(' + m[2].trim() + ')');
  }
  return bad;
}
['en', 'zh'].forEach(function (lang) {
  const h = lang === 'en' ? en : zh;
  const bad = paramTShadow(h);
  check(lang + ' no i18n param-shadowing (param `t` must not call t())', bad.length === 0, bad.join('; '));
});

// body-level fn extractor (sv() lives in a body script, not <head>; fnSrc inside
// the 3b IIFE is scoped away, so 3c needs its own). Keeps a leading `async `.
function fnFrom(html, name) {
  const start = html.indexOf('function ' + name + '(');
  if (start < 0) return '';
  const s0 = start - 6;
  const from = (s0 >= 0 && html.slice(s0, start) === 'async ') ? s0 : start;
  let i = html.indexOf('{', start), depth = 0;
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    else if (html[i] === '}') { depth--; if (depth === 0) break; }
  }
  return html.slice(from, i + 1);
}

// ── 3c. sv() save-button regression (Config / ACL / Chnroute sub-tabs) ──
// User report: after clicking Save the button permanently relabelled to
// '保存 配置' (sv() reverted to tf('Save {0}',[t(tab)])) and no later save stuck
// (sv() never wrote the PUT body back to the cfgD snapshot, so the next sub-tab
// switch rebuilt the editors from stale pre-save content). sv() must now revert
// to the resting label t('Save') = '保存', re-enable, and mirror saved text into
// cfgD; a failed PUT must surface the backend reason instead of a bare 'Error'.
async function checkSvRegression() {
  // the en block above reset t() to identity — restore the zh dict/t first.
  try { (0, eval)(headInlineScripts(zh)); }
  catch (e) { check('zh head restore for sv()', false, e && e.message); return; }
  const src = fnFrom(zh, 'sv');
  if (!src) { check('zh sv() source found', false); return; }
  try { (0, eval)(src); }
  catch (e) { check('zh eval sv()', false, e && e.message); return; }

  const mkBtn = function () { return { disabled: false, textContent: '' }; };
  const realFetch = global.fetch, realTO = global.setTimeout,
        realEvent = global.event, realAlert = global.alert;
  global.setTimeout = function (fn) { fn(); };   // revert fires synchronously, no 2s wait
  try {
    // success: cfgD mirrors the PUT body; button back to resting '保存', enabled
    const b = mkBtn();
    global.event = { target: b };
    global.cfgD = {};
    global.cm_cfg = { getValue: function () { return '{"proxy_group":"auto"}'; } };
    global.fetch = function () { return Promise.resolve({ ok: true }); };
    await sv('cfg');
    check('sv success: cfgD synced', global.cfgD.cfg === '{"proxy_group":"auto"}', JSON.stringify(global.cfgD.cfg));
    check('sv success: revert label', b.textContent === '保存', JSON.stringify(b.textContent));
    check('sv success: re-enabled', b.disabled === false);

    // failure: backend reason surfaced through alert; button still reverts
    let lastAlert = '';
    const b2 = mkBtn();
    global.event = { target: b2 };
    global.alert = function (m) { lastAlert = m; };
    global.fetch = function () {
      return Promise.resolve({ ok: false, status: 400, text: function () { return Promise.resolve('validation failed'); } });
    };
    await sv('cfg');
    check('sv fail: backend reason surfaced', lastAlert.indexOf('Save failed: ') === 0 && lastAlert.indexOf('validation failed') >= 0, JSON.stringify(lastAlert));
    check('sv fail: revert label', b2.textContent === '保存', JSON.stringify(b2.textContent));
    check('sv fail: re-enabled', b2.disabled === false);
  } catch (e) {
    check('sv() regression run', false, e && e.stack || e);
  } finally {
    global.fetch = realFetch; global.setTimeout = realTO;
    global.event = realEvent; global.alert = realAlert;
    delete global.cfgD; delete global.cm_cfg;
  }
}

checkSvRegression().then(function () {
  console.log(fails ? ('\n' + fails + ' FAILURE(S)') : '\nALL PASS');
  process.exit(fails ? 1 : 0);
}).catch(function (e) {
  console.log('CRASH ' + (e && e.stack || e));
  process.exit(1);
});
