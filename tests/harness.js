'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'pre-tool-use.js');

/**
 * Runs the pre-tool-use script with the given event as stdin.
 * Returns { decision: 'allow'|'ask'|'deny', reason: string }
 *
 * 'allow' is returned when the script exits cleanly with no stdout
 * (no guardrail triggered) as well as when permissionDecision is 'allow'.
 */
function run(event) {
  const result = spawnSync('node', [SCRIPT], {
    input: JSON.stringify(event),
    encoding: 'utf8',
    timeout: 5000,
  });

  if (result.error) throw new Error(`Failed to spawn script: ${result.error.message}`);

  const stdout = (result.stdout || '').trim();
  if (!stdout) return { decision: 'allow', reason: '' };

  try {
    const parsed = JSON.parse(stdout);
    const decision = parsed?.hookSpecificOutput?.permissionDecision ?? 'allow';
    const reason  = parsed?.hookSpecificOutput?.permissionDecisionReason ?? '';
    return { decision, reason };
  } catch (_) {
    return { decision: 'allow', reason: '', raw: stdout };
  }
}

module.exports = { run };
