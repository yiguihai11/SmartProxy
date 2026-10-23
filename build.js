const fs = require('fs');

// check dashboard.html's js syntax
const html = fs.readFileSync('internal/admin/dashboard.html', 'utf8');

// check all dashboard.html's inline js syntax
let allJs = '';
const scriptRegex = /<script(?:\s+[^>]*)?>([\s\S]*?)<\/script>/gi;
let match;
let scriptIndex = 0;
while ((match = scriptRegex.exec(html)) !== null) {
  scriptIndex++;
  const code = match[1];
  if (!code.trim()) continue; // external src script
  try {
    new Function(code);
    allJs += '\n' + code;
  } catch (e) {
    console.error(`ERROR: dashboard.html script block #${scriptIndex} syntax error:`);
    console.error('  ' + e.message);
    process.exit(1);
  }
}
console.log('  -> dashboard.js syntax OK (all script blocks validated)');

const js = allJs;

// Cross-check: an immediate property access on getElementById('X').prop must reference a
// static id="X" in the HTML. Guards against "element removed from HTML but a reset/access
// line left behind" bugs (e.g. proxy-obfs-method). Dynamically-created elements are
// always reached through a guarded var, never an immediate property access, so they do
// not match this pattern.
const idSet = new Set();
for (const m of html.matchAll(/id="([^"]+)"/g)) idSet.add(m[1]);
const missing = [];
const refRe = /getElementById\('([^']+)'\)\s*\.\s*\w+/g;
let ref;
while ((ref = refRe.exec(js)) !== null) {
  if (!idSet.has(ref[1])) missing.push(ref[1]);
}
if (missing.length) {
  console.error('ERROR: getElementById() targets missing from HTML: ' + missing.join(', '));
  process.exit(1);
}
