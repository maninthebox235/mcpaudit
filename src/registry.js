'use strict';

/**
 * MCP Trust Registry — stub for future API integration.
 * Will connect to a centralized registry of audited MCP servers.
 */

const REGISTRY_URL = process.env.MCPAUDIT_REGISTRY_URL || 'https://registry.mcpaudit.dev/api/v1';

async function queryRegistry(packageName) {
  // TODO: Implement actual API call
  return {
    package: packageName,
    status: 'unverified',
    message: `Registry lookup for "${packageName}" is not yet available. Coming soon.`,
    registryUrl: REGISTRY_URL,
  };
}

async function submitReport(packageName, report) {
  // TODO: Implement actual API submission
  return {
    package: packageName,
    submitted: false,
    message: 'Report submission is not yet available. Coming soon.',
    registryUrl: REGISTRY_URL,
  };
}

module.exports = { queryRegistry, submitReport };
