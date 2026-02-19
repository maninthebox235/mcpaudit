'use strict';

const chalk = require('chalk');
const Table = require('cli-table3');
const path = require('path');

const SEVERITY_COLORS = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
};

function formatFindings(findings, format = 'table') {
  switch (format) {
    case 'json': return formatJSON(findings);
    case 'html': return formatHTML(findings);
    case 'table':
    default: return formatTable(findings);
  }
}

function formatTable(findings) {
  if (findings.length === 0) {
    return chalk.green.bold('✅ No vulnerabilities found!');
  }

  const table = new Table({
    head: [
      chalk.white.bold('Sev'),
      chalk.white.bold('Rule'),
      chalk.white.bold('File'),
      chalk.white.bold('Line'),
      chalk.white.bold('Detail'),
    ],
    colWidths: [10, 22, 30, 6, 50],
    wordWrap: true,
    style: { head: [], border: ['grey'] },
  });

  for (const f of findings) {
    const sevFn = SEVERITY_COLORS[f.severity] || chalk.white;
    const shortFile = f.file ? path.basename(f.file) : '?';
    table.push([
      sevFn(f.severity.toUpperCase()),
      f.ruleId,
      shortFile,
      f.line || '-',
      f.detail,
    ]);
  }

  return table.toString();
}

function formatJSON(findings) {
  return JSON.stringify({
    tool: 'mcpaudit',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    totalFindings: findings.length,
    summary: {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
    },
    findings,
  }, null, 2);
}

function formatHTML(findings) {
  const rows = findings.map(f => {
    const sevClass = f.severity;
    return `<tr class="${sevClass}">
      <td><span class="badge ${sevClass}">${f.severity.toUpperCase()}</span></td>
      <td>${esc(f.ruleId)}</td>
      <td>${esc(f.file || '')}</td>
      <td>${f.line || '-'}</td>
      <td>${esc(f.detail)}</td>
    </tr>`;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MCPAudit Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2rem; background: #0d1117; color: #c9d1d9; }
  h1 { color: #58a6ff; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #21262d; }
  th { background: #161b22; color: #8b949e; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
  .critical .badge, .badge.critical { background: #da3633; color: #fff; }
  .high .badge, .badge.high { background: #f85149; color: #fff; }
  .medium .badge, .badge.medium { background: #d29922; color: #000; }
  .low .badge, .badge.low { background: #388bfd; color: #fff; }
  .summary { margin: 1rem 0; padding: 1rem; background: #161b22; border-radius: 8px; }
  .summary span { margin-right: 1.5rem; }
</style>
</head>
<body>
<h1>🔒 MCPAudit Report</h1>
<p>Generated: ${new Date().toISOString()}</p>
<div class="summary">
  <span><strong>${findings.filter(f => f.severity === 'critical').length}</strong> Critical</span>
  <span><strong>${findings.filter(f => f.severity === 'high').length}</strong> High</span>
  <span><strong>${findings.filter(f => f.severity === 'medium').length}</strong> Medium</span>
  <span><strong>${findings.filter(f => f.severity === 'low').length}</strong> Low</span>
  <span>| <strong>${findings.length}</strong> Total</span>
</div>
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Detail</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
</body>
</html>`;
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

module.exports = { formatFindings };
