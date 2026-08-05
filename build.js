const fs = require('fs');

// 检查 dashboard.html 的 js 语法
const html = fs.readFileSync('internal/admin/dashboard.html', 'utf8');

// 找到主 script 块
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
