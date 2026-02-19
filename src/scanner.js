'use strict';

const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { glob } = require('glob');

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

// ── Rule definitions ────────────────────────────────────────────────

const RULES = [
  {
    id: 'SHELL_INJECTION',
    name: 'Shell Injection',
    severity: 'critical',
    description: 'Detects use of child_process exec/execSync with dynamic arguments',
    check: checkShellInjection,
  },
  {
    id: 'ENV_LEAK',
    name: 'Environment Variable Leak',
    severity: 'high',
    description: 'Detects process.env values passed to responses or logs without filtering',
    check: checkEnvLeak,
  },
  {
    id: 'FS_OVERREACH',
    name: 'Filesystem Overreach',
    severity: 'high',
    description: 'Detects filesystem operations outside expected directories or on sensitive paths',
    check: checkFilesystemOverreach,
  },
  {
    id: 'SSRF',
    name: 'Server-Side Request Forgery',
    severity: 'high',
    description: 'Detects HTTP requests with user-controlled URLs',
    check: checkSSRF,
  },
  {
    id: 'HARDCODED_SECRETS',
    name: 'Hardcoded Secrets',
    severity: 'critical',
    description: 'Detects hardcoded API keys, tokens, passwords',
    check: checkHardcodedSecrets,
  },
  {
    id: 'SQL_INJECTION',
    name: 'SQL Injection',
    severity: 'critical',
    description: 'Detects string concatenation or template literals in SQL queries',
    check: checkSQLInjection,
  },
  {
    id: 'EXCESSIVE_PERMISSIONS',
    name: 'Excessive Permissions',
    severity: 'medium',
    description: 'Detects overly broad tool capabilities or permission grants',
    check: checkExcessivePermissions,
  },
  {
    id: 'MISSING_VALIDATION',
    name: 'Missing Input Validation',
    severity: 'medium',
    description: 'Detects tool handlers that use parameters without validation',
    check: checkMissingValidation,
  },
  {
    id: 'UNSAFE_EVAL',
    name: 'Unsafe Eval',
    severity: 'critical',
    description: 'Detects eval(), Function(), vm.runInNewContext with dynamic input',
    check: checkUnsafeEval,
  },
  {
    id: 'PROTOTYPE_POLLUTION',
    name: 'Prototype Pollution',
    severity: 'high',
    description: 'Detects patterns that may allow prototype pollution',
    check: checkPrototypePollution,
  },
  {
    id: 'PATH_TRAVERSAL',
    name: 'Path Traversal',
    severity: 'high',
    description: 'Detects path concatenation without sanitization',
    check: checkPathTraversal,
  },
  {
    id: 'UNVALIDATED_REDIRECT',
    name: 'Unvalidated Redirect',
    severity: 'medium',
    description: 'Detects redirects using user-controlled URLs',
    check: checkUnvalidatedRedirect,
  },
];

// ── Main entry ──────────────────────────────────────────────────────

async function scanPackage(targetPath, opts = {}) {
  const { minSeverity = 'low', ignoreRules = [] } = opts;
  const minSev = SEVERITY_ORDER[minSeverity] || 0;

  if (!fs.existsSync(targetPath)) {
    throw new Error(`Target path does not exist: ${targetPath}`);
  }

  const stat = fs.statSync(targetPath);
  let files;
  if (stat.isFile()) {
    files = [targetPath];
  } else {
    files = await glob('**/*.{js,mjs,cjs,ts}', {
      cwd: targetPath,
      absolute: true,
      ignore: ['**/node_modules/**', '**/dist/**', '**/.git/**', '**/coverage/**'],
    });
  }

  if (files.length === 0) {
    console.log('No JS/TS files found.');
    return [];
  }

  console.log(`Scanning ${files.length} file(s)...`);

  const allFindings = [];

  for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');
    let ast;
    try {
      ast = acorn.parse(source, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        allowImportExportEverywhere: true,
        allowAwaitOutsideFunction: true,
        allowReturnOutsideFunction: true,
        allowHashBang: true,
        locations: true,
      });
    } catch {
      // If acorn can't parse (e.g. TypeScript), fall back to regex-based scanning
      const regexFindings = regexFallback(source, file);
      allFindings.push(...regexFindings);
      continue;
    }

    const activeRules = RULES.filter(
      r => !ignoreRules.includes(r.id) && SEVERITY_ORDER[r.severity] >= minSev
    );

    for (const rule of activeRules) {
      const findings = rule.check(ast, source, file);
      allFindings.push(...findings);
    }
  }

  // Sort by severity desc
  allFindings.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));

  return allFindings;
}

// ── Helpers ─────────────────────────────────────────────────────────

function finding(rule, file, line, detail) {
  return {
    ruleId: rule.id || rule,
    ruleName: rule.name || rule,
    severity: rule.severity || 'medium',
    file: file,
    line: line,
    detail: detail,
  };
}

function getLine(node) {
  return node.loc ? node.loc.start.line : 0;
}

/** Check if a node is a require('x') call for a given module */
function isRequireOf(node, modName) {
  return (
    node.type === 'CallExpression' &&
    node.callee.type === 'Identifier' &&
    node.callee.name === 'require' &&
    node.arguments.length > 0 &&
    node.arguments[0].type === 'Literal' &&
    node.arguments[0].value === modName
  );
}

/** Check if node is a member expression matching obj.prop */
function isMember(node, obj, prop) {
  return (
    node.type === 'MemberExpression' &&
    node.object.type === 'Identifier' &&
    node.object.name === obj &&
    ((node.property.type === 'Identifier' && node.property.name === prop) ||
      (node.property.type === 'Literal' && node.property.value === prop))
  );
}

function nodeContainsDynamic(node) {
  if (node.type === 'TemplateLiteral' && node.expressions.length > 0) return true;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return containsIdentifierOrMember(node);
  }
  if (node.type === 'Identifier') return true;
  if (node.type === 'MemberExpression') return true;
  if (node.type === 'CallExpression') return true;
  return false;
}

function containsIdentifierOrMember(node) {
  if (!node) return false;
  if (node.type === 'Identifier' || node.type === 'MemberExpression') return true;
  if (node.type === 'BinaryExpression') {
    return containsIdentifierOrMember(node.left) || containsIdentifierOrMember(node.right);
  }
  if (node.type === 'TemplateLiteral') return node.expressions.length > 0;
  return false;
}

// ── Rule implementations ────────────────────────────────────────────

function checkShellInjection(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'SHELL_INJECTION');
  const dangerousFns = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);

  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      // child_process.exec(...) or cp.exec(...)
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && dangerousFns.has(callee.property.name)) {
        const arg = node.arguments[0];
        if (arg && nodeContainsDynamic(arg)) {
          results.push(finding(rule, file, getLine(node),
            `${callee.property.name}() called with dynamic argument — potential shell injection`));
        }
      }
      // Direct exec(...) after destructuring
      if (callee.type === 'Identifier' && dangerousFns.has(callee.name)) {
        const arg = node.arguments[0];
        if (arg && nodeContainsDynamic(arg)) {
          results.push(finding(rule, file, getLine(node),
            `${callee.name}() called with dynamic argument — potential shell injection`));
        }
      }
    },
  });
  return results;
}

function checkEnvLeak(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'ENV_LEAK');

  walk.simple(ast, {
    MemberExpression(node) {
      if (isMember(node, 'process', 'env')) {
        // Check parent context — if it's inside a return, response, console.log, JSON.stringify
        // We flag all process.env access in MCP servers as noteworthy
        results.push(finding(rule, file, getLine(node),
          'process.env accessed — ensure secrets are not leaked in tool responses'));
      }
    },
  });

  // Dedupe to max 3 per file
  if (results.length > 3) {
    const trimmed = results.slice(0, 3);
    trimmed.push(finding(rule, file, 0, `... and ${results.length - 3} more process.env accesses`));
    return trimmed;
  }
  return results;
}

function checkFilesystemOverreach(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'FS_OVERREACH');
  const sensitivePaths = ['/etc/', '/root', '/home', '~/', 'C:\\Windows', '..'];
  const fsMethods = new Set([
    'readFileSync', 'readFile', 'writeFileSync', 'writeFile',
    'unlinkSync', 'unlink', 'rmdirSync', 'rmdir', 'rmSync',
    'readdirSync', 'readdir', 'mkdirSync', 'mkdir',
    'copyFileSync', 'copyFile', 'renameSync', 'rename',
    'chmodSync', 'chmod', 'chownSync', 'chown',
  ]);

  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && fsMethods.has(callee.property.name)) {
        const arg = node.arguments[0];
        if (arg) {
          // Check for dynamic paths
          if (nodeContainsDynamic(arg)) {
            results.push(finding(rule, file, getLine(node),
              `${callee.property.name}() with dynamic path — verify path is sandboxed`));
          }
          // Check for sensitive hardcoded paths
          if (arg.type === 'Literal' && typeof arg.value === 'string') {
            for (const sp of sensitivePaths) {
              if (arg.value.includes(sp)) {
                results.push(finding(rule, file, getLine(node),
                  `${callee.property.name}() accesses sensitive path: ${arg.value}`));
                break;
              }
            }
          }
        }
      }
    },
  });
  return results;
}

function checkSSRF(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'SSRF');
  const httpFns = new Set(['fetch', 'get', 'post', 'put', 'patch', 'delete', 'request', 'axios']);

  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      const name = callee.type === 'Identifier' ? callee.name :
        (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') ? callee.property.name : null;

      if (name && httpFns.has(name)) {
        const arg = node.arguments[0];
        if (arg && nodeContainsDynamic(arg)) {
          results.push(finding(rule, file, getLine(node),
            `${name}() called with dynamic URL — potential SSRF`));
        }
      }
    },
  });
  return results;
}

function checkHardcodedSecrets(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'HARDCODED_SECRETS');
  const secretPatterns = [
    { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi, label: 'API key' },
    { pattern: /(?:secret|token|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi, label: 'Secret/token/password' },
    { pattern: /(?:sk|pk)[-_](?:live|test)[-_][A-Za-z0-9]{20,}/g, label: 'Stripe-style key' },
    { pattern: /ghp_[A-Za-z0-9]{36,}/g, label: 'GitHub PAT' },
    { pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/g, label: 'AWS access key' },
    { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, label: 'Private key' },
    { pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, label: 'Bearer token' },
  ];

  const lines = source.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip comments
    if (line.trim().startsWith('//') && line.includes('example')) continue;
    for (const { pattern, label } of secretPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        results.push(finding(rule, file, i + 1, `Possible ${label} found`));
      }
    }
  }
  return results;
}

function checkSQLInjection(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'SQL_INJECTION');
  const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b/i;

  walk.simple(ast, {
    TemplateLiteral(node) {
      if (node.expressions.length > 0) {
        const raw = node.quasis.map(q => q.value.raw).join('');
        if (sqlKeywords.test(raw)) {
          results.push(finding(rule, file, getLine(node),
            'SQL query built with template literal interpolation — use parameterized queries'));
        }
      }
    },
    BinaryExpression(node) {
      if (node.operator === '+') {
        const src = source.slice(node.start, node.end);
        if (sqlKeywords.test(src) && containsIdentifierOrMember(node)) {
          results.push(finding(rule, file, getLine(node),
            'SQL query built with string concatenation — use parameterized queries'));
        }
      }
    },
  });
  return results;
}

function checkExcessivePermissions(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'EXCESSIVE_PERMISSIONS');

  // Check for wildcard permissions or overly broad tool descriptions
  const lines = source.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/['"]?\*['"]?\s*/.test(line) && /permission|scope|allow|grant|role/i.test(line)) {
      results.push(finding(rule, file, i + 1, 'Wildcard permission detected'));
    }
  }

  // Check for tools that expose filesystem, shell, network broadly
  walk.simple(ast, {
    ObjectExpression(node) {
      for (const prop of node.properties) {
        if (prop.type !== 'Property') continue;
        const key = prop.key.type === 'Identifier' ? prop.key.name : prop.key.value;
        if (key === 'name' && prop.value.type === 'Literal') {
          const toolName = prop.value.value;
          if (typeof toolName === 'string' && /^(execute|run|shell|eval|admin)/i.test(toolName)) {
            results.push(finding(rule, file, getLine(node),
              `Tool "${toolName}" has a high-privilege name — review carefully`));
          }
        }
      }
    },
  });
  return results;
}

function checkMissingValidation(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'MISSING_VALIDATION');

  // Look for MCP tool handler patterns: functions that destructure params and use them directly
  walk.simple(ast, {
    FunctionDeclaration(node) { checkFnBody(node, results, rule, file); },
    FunctionExpression(node) { checkFnBody(node, results, rule, file); },
    ArrowFunctionExpression(node) { checkFnBody(node, results, rule, file); },
  });

  return results;
}

function checkFnBody(node, results, rule, file) {
  // Look for params destructured then used in dangerous sinks without validation
  const params = [];
  for (const p of node.params) {
    if (p.type === 'ObjectPattern') {
      for (const prop of p.properties) {
        if (prop.value && prop.value.type === 'Identifier') {
          params.push(prop.value.name);
        }
      }
    }
  }
  if (params.length === 0) return;

  const body = node.body;
  if (!body) return;

  let hasValidation = false;
  let usesDangerousSink = false;

  walk.simple(body, {
    IfStatement() { hasValidation = true; },
    CallExpression(n) {
      const callee = n.callee;
      const name = callee.type === 'Identifier' ? callee.name :
        (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') ? callee.property.name : null;
      if (name && /^(exec|query|fetch|readFile|writeFile|spawn)/.test(name)) {
        usesDangerousSink = true;
      }
      // Validation function calls
      if (name && /^(validate|sanitize|check|assert|zod|schema)/.test(name)) {
        hasValidation = true;
      }
    },
  });

  if (usesDangerousSink && !hasValidation) {
    results.push(finding(rule, file, getLine(node),
      `Function uses destructured params in dangerous sinks without apparent validation`));
  }
}

function checkUnsafeEval(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'UNSAFE_EVAL');

  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      // eval(...)
      if (callee.type === 'Identifier' && callee.name === 'eval') {
        results.push(finding(rule, file, getLine(node), 'eval() used — extremely dangerous'));
      }
      // new Function(...)
      if (node.type === 'CallExpression' && callee.type === 'Identifier' && callee.name === 'Function') {
        results.push(finding(rule, file, getLine(node), 'Function() constructor used — equivalent to eval'));
      }
      // vm.runInNewContext / vm.runInThisContext
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' &&
          /^(runInNewContext|runInThisContext|compileFunction)$/.test(callee.property.name)) {
        results.push(finding(rule, file, getLine(node),
          `${callee.property.name}() used — code execution risk`));
      }
      // setTimeout/setInterval with string
      if (callee.type === 'Identifier' && (callee.name === 'setTimeout' || callee.name === 'setInterval')) {
        const arg = node.arguments[0];
        if (arg && (arg.type === 'Literal' && typeof arg.value === 'string') || (arg && arg.type === 'TemplateLiteral')) {
          results.push(finding(rule, file, getLine(node),
            `${callee.name}() with string argument — equivalent to eval`));
        }
      }
    },
    NewExpression(node) {
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
        results.push(finding(rule, file, getLine(node), 'new Function() used — equivalent to eval'));
      }
    },
  });
  return results;
}

function checkPrototypePollution(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'PROTOTYPE_POLLUTION');

  walk.simple(ast, {
    AssignmentExpression(node) {
      // obj[key][key2] = value  (computed nested assignment)
      const left = node.left;
      if (left.type === 'MemberExpression' && left.computed &&
          left.object.type === 'MemberExpression' && left.object.computed) {
        results.push(finding(rule, file, getLine(node),
          'Nested computed property assignment — potential prototype pollution'));
      }
    },
    CallExpression(node) {
      const callee = node.callee;
      // Object.assign with spread from user input
      if (callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' && callee.object.name === 'Object' &&
          callee.property.type === 'Identifier' && callee.property.name === 'assign') {
        results.push(finding(rule, file, getLine(node),
          'Object.assign() used — verify source objects are trusted'));
      }
      // _.merge, _.defaultsDeep, etc.
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' &&
          /^(merge|defaultsDeep|extend)$/.test(callee.property.name)) {
        results.push(finding(rule, file, getLine(node),
          `${callee.property.name}() used — common prototype pollution vector`));
      }
    },
  });
  return results;
}

function checkPathTraversal(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'PATH_TRAVERSAL');

  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      // path.join / path.resolve with dynamic args
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' &&
          (callee.property.name === 'join' || callee.property.name === 'resolve')) {
        for (const arg of node.arguments) {
          if (nodeContainsDynamic(arg)) {
            // Check if there's a .startsWith or .includes('..') check nearby — hard to do statically
            results.push(finding(rule, file, getLine(node),
              `path.${callee.property.name}() with dynamic input — ensure traversal is prevented`));
            break;
          }
        }
      }
    },
    BinaryExpression(node) {
      if (node.operator === '+') {
        // String concat with '/' and a variable
        const src = source.slice(node.start, Math.min(node.end, node.start + 200));
        if (/[\/\\]/.test(src) && containsIdentifierOrMember(node)) {
          // Only flag if it looks path-like
          if (/\.(js|json|txt|html|css|md|log|csv|xml|yaml|yml|env)/.test(src) || /\//.test(src)) {
            results.push(finding(rule, file, getLine(node),
              'Path built with string concatenation — potential path traversal'));
          }
        }
      }
    },
  });
  return results;
}

function checkUnvalidatedRedirect(ast, source, file) {
  const results = [];
  const rule = RULES.find(r => r.id === 'UNVALIDATED_REDIRECT');

  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      // res.redirect(userInput)
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' &&
          callee.property.name === 'redirect') {
        const arg = node.arguments[node.arguments.length - 1]; // last arg is URL
        if (arg && nodeContainsDynamic(arg)) {
          results.push(finding(rule, file, getLine(node),
            'redirect() with dynamic URL — validate against allowlist'));
        }
      }
      // window.location = / location.href =
    },
    AssignmentExpression(node) {
      const left = node.left;
      if (left.type === 'MemberExpression' && left.property.type === 'Identifier' &&
          (left.property.name === 'href' || left.property.name === 'location')) {
        if (nodeContainsDynamic(node.right)) {
          results.push(finding(rule, file, getLine(node),
            'Location/href set to dynamic value — potential open redirect'));
        }
      }
    },
  });
  return results;
}

// ── Regex fallback for unparseable files ────────────────────────────

function regexFallback(source, file) {
  const results = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\beval\s*\(/.test(line)) {
      results.push({ ruleId: 'UNSAFE_EVAL', ruleName: 'Unsafe Eval', severity: 'critical', file, line: i + 1, detail: 'eval() detected (regex fallback)' });
    }
    if (/child_process/.test(line) && /exec/.test(line)) {
      results.push({ ruleId: 'SHELL_INJECTION', ruleName: 'Shell Injection', severity: 'critical', file, line: i + 1, detail: 'child_process exec detected (regex fallback)' });
    }
    if (/(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9]{16,}['"]/i.test(line)) {
      results.push({ ruleId: 'HARDCODED_SECRETS', ruleName: 'Hardcoded Secrets', severity: 'critical', file, line: i + 1, detail: 'Possible hardcoded secret (regex fallback)' });
    }
  }
  return results;
}

module.exports = { scanPackage, RULES };
