const fs = require('fs');

// check dashboard.html's js syntax
const html = fs.readFileSync('internal/admin/dashboard.html', 'utf8');

// locate the main script block
const start = html.indexOf('<script>\n');
const end = html.indexOf('</script>', start + 1);
if (start === -1 || end === -1) {
  console.error('ERROR: <script> block not found');
  process.exit(1);
}

const js = html.substring(start + 8, end);
try {
  new Function(js);
  console.log('  -> dashboard.js syntax OK');
} catch (e) {
  console.error('ERROR: dashboard.js syntax error');
  console.error('  ' + e.message);
  process.exit(1);
}

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
