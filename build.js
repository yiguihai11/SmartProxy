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
