'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { scanPackage } = require('../src/scanner');
const { formatFindings } = require('../src/reporter');

const fixtureDir = path.join(__dirname, 'fixtures', 'sample-pkg');
const fixtureFile = path.join(fixtureDir, 'server.js');

describe('scanPackage', () => {
  it('scans a package directory via glob brace patterns', async () => {
    const findings = await scanPackage(fixtureDir, { minSeverity: 'low' });
    assert.ok(Array.isArray(findings));
    assert.ok(
      findings.some((f) => f.ruleId === 'UNSAFE_EVAL'),
      `expected UNSAFE_EVAL finding, got: ${JSON.stringify(findings)}`
    );
  });

  it('scans a single file target', async () => {
    const findings = await scanPackage(fixtureFile, { minSeverity: 'critical' });
    assert.ok(Array.isArray(findings));
    assert.ok(findings.length >= 1);
  });

  it('rejects missing paths', async () => {
    await assert.rejects(
      () => scanPackage(path.join(fixtureDir, 'missing-dir')),
      /does not exist/
    );
  });
});

describe('formatFindings', () => {
  it('formats empty findings as json', () => {
    const out = formatFindings([], 'json');
    const parsed = JSON.parse(out);
    assert.equal(parsed.tool, 'mcpaudit');
    assert.equal(parsed.totalFindings, 0);
    assert.deepEqual(parsed.findings, []);
  });
});
