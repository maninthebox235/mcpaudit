'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const cli = path.join(__dirname, '..', 'src', 'index.js');

describe('mcpaudit CLI', () => {
  it('prints help for --help', () => {
    const result = spawnSync(process.execPath, [cli, '--help'], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0);
    assert.match(result.stdout, /Usage: mcpaudit/);
    assert.match(result.stdout, /scan/);
  });

  it('prints version for --version', () => {
    const result = spawnSync(process.execPath, [cli, '--version'], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0);
    assert.match(result.stdout.trim(), /^0\.1\.0$/);
  });
});
