# 🔒 MCPAudit

<!-- badges -->
[![npm version](https://img.shields.io/npm/v/mcpaudit)](https://www.npmjs.com/package/mcpaudit)
[![license](https://img.shields.io/npm/l/mcpaudit)](LICENSE)

**Security audit tool for MCP (Model Context Protocol) server packages.**

MCPAudit scans MCP server source code for common vulnerabilities using AST analysis — shell injection, SSRF, hardcoded secrets, SQL injection, path traversal, unsafe eval, and more.

## Install

```bash
npm install -g mcpaudit
```

## Usage

### Scan a package

```bash
mcpaudit scan ./my-mcp-server
mcpaudit scan ./my-mcp-server --format json
mcpaudit scan ./my-mcp-server --format html -o report.html
mcpaudit scan ./server.js --severity high
mcpaudit scan ./my-mcp-server --ignore ENV_LEAK,EXCESSIVE_PERMISSIONS
```

### Generate a report

```bash
mcpaudit report ./my-mcp-server -o audit.html
```

### Query the trust registry

```bash
mcpaudit registry lookup --package @example/mcp-server
```

## What it checks

| Rule | Severity | Description |
|------|----------|-------------|
| `SHELL_INJECTION` | Critical | `exec()`/`spawn()` with dynamic args |
| `UNSAFE_EVAL` | Critical | `eval()`, `new Function()`, `vm.runInNewContext()` |
| `HARDCODED_SECRETS` | Critical | API keys, tokens, passwords in source |
| `SQL_INJECTION` | Critical | String interpolation in SQL queries |
| `SSRF` | High | HTTP requests with user-controlled URLs |
| `FS_OVERREACH` | High | Filesystem ops on sensitive/dynamic paths |
| `ENV_LEAK` | High | `process.env` exposed in responses |
| `PROTOTYPE_POLLUTION` | High | Unsafe deep merge / computed property assignment |
| `PATH_TRAVERSAL` | High | Unsanitized path construction |
| `EXCESSIVE_PERMISSIONS` | Medium | Wildcard permissions, high-privilege tool names |
| `MISSING_VALIDATION` | Medium | Params used in sinks without validation |
| `UNVALIDATED_REDIRECT` | Medium | Redirects with dynamic URLs |

## Output formats

- **table** (default) — colored CLI table
- **json** — structured JSON with summary
- **html** — dark-themed HTML report

## Exit codes

- `0` — No high/critical findings
- `1` — High severity findings
- `2` — Critical severity findings

## License

MIT
