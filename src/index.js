#!/usr/bin/env node
'use strict';

const { Command } = require('commander');
const path = require('path');
const { scanPackage } = require('./scanner');
const { formatFindings } = require('./reporter');
const { queryRegistry, submitReport } = require('./registry');

const program = new Command();

program
  .name('mcpaudit')
  .description('Security audit tool for MCP server packages')
  .version('0.1.0');

program
  .command('scan <target>')
  .description('Scan an MCP server package for vulnerabilities')
  .option('-f, --format <format>', 'Output format: json, table, html', 'table')
  .option('-o, --output <file>', 'Write output to file')
  .option('--severity <level>', 'Minimum severity: low, medium, high, critical', 'low')
  .option('--ignore <rules>', 'Comma-separated rule IDs to ignore')
  .action(async (target, opts) => {
    const targetPath = path.resolve(target);
    console.log(`\n🔍 Scanning ${targetPath} ...\n`);

    try {
      const findings = await scanPackage(targetPath, {
        minSeverity: opts.severity,
        ignoreRules: opts.ignore ? opts.ignore.split(',') : [],
      });

      const output = formatFindings(findings, opts.format);

      if (opts.output) {
        require('fs').writeFileSync(opts.output, output, 'utf8');
        console.log(`Report written to ${opts.output}`);
      } else {
        console.log(output);
      }

      const critical = findings.filter(f => f.severity === 'critical').length;
      const high = findings.filter(f => f.severity === 'high').length;
      console.log(`\n📊 ${findings.length} finding(s): ${critical} critical, ${high} high\n`);
      process.exit(critical > 0 ? 2 : high > 0 ? 1 : 0);
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command('report <target>')
  .description('Generate a full audit report for a package')
  .option('-f, --format <format>', 'Output format: json, table, html', 'html')
  .option('-o, --output <file>', 'Write output to file')
  .action(async (target, opts) => {
    const targetPath = path.resolve(target);
    try {
      const findings = await scanPackage(targetPath, {});
      const output = formatFindings(findings, opts.format);
      if (opts.output) {
        require('fs').writeFileSync(opts.output, output, 'utf8');
        console.log(`Report written to ${opts.output}`);
      } else {
        console.log(output);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command('registry [action]')
  .description('Query the MCP trust registry (lookup/submit)')
  .option('-p, --package <name>', 'Package name to look up')
  .action(async (action = 'lookup', opts) => {
    if (action === 'lookup') {
      const result = await queryRegistry(opts.package || 'unknown');
      console.log(JSON.stringify(result, null, 2));
    } else if (action === 'submit') {
      const result = await submitReport(opts.package || 'unknown', {});
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log('Unknown action. Use: lookup, submit');
    }
  });

program.parse();
