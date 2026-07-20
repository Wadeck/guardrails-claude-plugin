'use strict';

// Regression test: hooks.json MUST have a wildcard PreToolUse matcher.
// Without it, MCP tools (mcp__*) never fire the hook in production, and the
// entire isWriteCapableTool / mcp-tools.js code path becomes dead code.
// This was a CRITICAL finding in the v4 audit.
//
// We use a synthetic test that reads hooks.json and asserts the matcher set
// includes "*", "" or undefined. The runner doesn't natively support this kind
// of assertion, so we encode it as a tool call that always returns 'allow' but
// throws (failing the test) if the structure is wrong.

const fs = require('fs');
const path = require('path');

const HOOKS_JSON = path.join(__dirname, '..', '..', 'hooks', 'hooks.json');

function validate() {
  const data = JSON.parse(fs.readFileSync(HOOKS_JSON, 'utf8'));
  const pre = data?.hooks?.PreToolUse;
  if (!Array.isArray(pre) || pre.length === 0) {
    throw new Error('hooks.json: PreToolUse must be a non-empty array');
  }
  const hasWildcard = pre.some((entry) => {
    const m = entry.matcher;
    return m === '*' || m === '' || m === undefined;
  });
  if (!hasWildcard) {
    throw new Error(
      `hooks.json: PreToolUse must include a wildcard matcher ("*", "", or omitted) ` +
      `to intercept MCP tools. Current matchers: ${JSON.stringify(pre.map((e) => e.matcher))}`,
    );
  }
}

// Run validation at module load - if it throws, the test runner aborts loading
// this file, marking it failed. The empty cases array means "no per-case
// assertions", but the load-time throw still surfaces in run-tests output.
validate();

module.exports = [];
