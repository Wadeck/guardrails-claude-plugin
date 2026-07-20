'use strict';

// Module-level imports must be wrapped: a missing helper or a desync between
// repo and cache (2026-06-21 incident) would make every require throw, locking
// the user out of every tool in every Claude Code session. If imports fail,
// exit 0 (allow) - the user has more pressing problems than guardrails right now.
let log, loadConfig, loadSecrets, findLeakedSecret;
let expandTilde, fromGitBash, normPath, extractBashWritePaths, getTargetPath, getTargetPaths, isWriteCapableTool;
let checkCrossHomeWrite, checkGuardrailsConfigWrite, checkFleetConfigWrite, checkSettingsWrite,
    checkMemoryWrite, checkSecretsFileWrite, checkProtectedFiles,
    checkSecretsNotGitignored, checkSecretsLeak, checkSecretsFileAccess,
    checkCategories, DECISION_RANK;
let path;
try {
  log = require('./log');
  ({ loadConfig, loadSecrets, findLeakedSecret } = require('./guardrails'));
  ({ expandTilde, fromGitBash, normPath, extractBashWritePaths, getTargetPath, getTargetPaths, isWriteCapableTool } = require('./paths'));
  ({ checkCrossHomeWrite, checkGuardrailsConfigWrite, checkFleetConfigWrite, checkSettingsWrite,
     checkMemoryWrite, checkSecretsFileWrite, checkProtectedFiles,
     checkSecretsNotGitignored, checkSecretsLeak, checkSecretsFileAccess,
     checkCategories, DECISION_RANK } = require('./checks'));
  path = require('path');
} catch (e) {
  // Last-resort fail-open. We can't even log because log itself may have failed.
  try { process.stderr.write(`[guardrails] import failed, allowing tool call: ${e.message}\n`); } catch (_) {}
  process.exit(0);
}

// Write-capable tools that this hook screens. Includes built-in write tools
// and any MCP tool whose name suggests a write operation (see isWriteCapableTool).
// Bash gets full category + path checks; non-Bash gets path checks only.

// ---------------------------------------------------------------------------
// Message builders (ask dialogs)
// ---------------------------------------------------------------------------

function buildSingleAskMessage(match, label) {
  // Category matches carry _rawDecision; their message is raw description text that needs wrapping.
  // Path-based matches are already self-contained (include [guardrails] prefix + question).
  if (match._rawDecision !== undefined) {
    const R = '\x1b[31m', Y = '\x1b[33m', BOLD = '\x1b[1m', RESET = '\x1b[0m';
    return [
      `[guardrails] ${match.message}`,
      '',
      'Do you want to allow this action?',
      '',
      `Rule    : ${Y}${BOLD}${match.name}${RESET}`,
      `Subject : ${R}${label}${RESET}`,
    ].join('\n');
  }
  return match.message;
}

function buildMultiAskMessage(askMatches, label) {
  const R = '\x1b[31m', Y = '\x1b[33m', W = '\x1b[1m\x1b[37m', RESET = '\x1b[0m';
  const BOX = 54;
  const chess = (len) => { let s = ''; for (let i = 0; i < len; i++) s += (i % 2 === 0 ? R : Y) + '═'; return s + RESET; };
  const pad   = (text, w) => text + ' '.repeat(Math.max(0, w - text.length));
  const row   = (text) => R + '║' + RESET + pad(' ' + text, BOX) + R + '║' + RESET;

  const title = `guardrails - ${askMatches.length} confirmations required`;
  const lines = [
    R + '╔' + chess(BOX) + R + '╗' + RESET,
    R + '║' + RESET + W + pad('  ' + title, BOX) + RESET + R + '║' + RESET,
    R + '╠' + chess(BOX) + R + '╣' + RESET,
  ];
  askMatches.forEach((m, i) => lines.push(row(`${i + 1}. ${m.name} - ${m.description ?? m.name}`)));
  lines.push(R + '╠' + chess(BOX) + R + '╣' + RESET);
  lines.push(R + '║' + RESET + Y + pad('  Approving allows ALL of the above.', BOX) + RESET + R + '║' + RESET);
  lines.push(R + '╚' + chess(BOX) + R + '╝' + RESET);
  lines.push('');
  lines.push(`Subject: ${label}`);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Accumulator: collect all matches → single decision
// ---------------------------------------------------------------------------

function resolveMatches(allMatches) {
  let worstDecision = null;
  let worstMatch    = null;
  const askMatches  = [];

  for (const match of allMatches) {
    if (match.decision === 'ask') askMatches.push(match);
    if (worstDecision === null || DECISION_RANK[match.decision] > DECISION_RANK[worstDecision]) {
      worstDecision = match.decision;
      worstMatch    = match;
    }
  }
  return { worstDecision, worstMatch, askMatches };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// Set to true once we have a parsed event and know the tool is write-capable.
// Errors AFTER this point are inside the security logic and must fail closed (deny).
// Errors BEFORE this point (require/import errors, malformed stdin) are bugs in
// the hook itself and must fail open (allow) - failing closed there can lock the
// user out of their entire Claude Code installation, as we learned the hard way.
let inSecurityLogic = false;

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  let event;
  try {
    event = JSON.parse(input);
  } catch (e) {
    log.error(`Failed to parse stdin: ${e.message}`);
    process.exit(0);
  }

  if (!isWriteCapableTool(event.tool_name)) process.exit(0);

  const isBash      = event.tool_name === 'Bash';
  const command     = isBash ? (event?.tool_input?.command ?? '') : '';
  const projectDir  = event?.cwd ?? process.cwd();

  // log.init can fail (disk full, permission change on .claude/logs/, stale
  // cache with a different log API). It's not attacker-controlled, so swallow
  // failures rather than denying every write-capable tool call.
  try { log.init(event); } catch (_) {}

  // Only flip the fail-closed flag AFTER log init. A log error before this
  // point is a reliability issue, not a security one.
  inSecurityLogic = true;

  function decide(decision, reason, trigger) {
    const output = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: decision,
        permissionDecisionReason: reason,
      },
    };
    log.info(`decision=${decision} | ${reason.split('\n')[0]}`);
    if (decision === 'deny' || decision === 'ask') {
      log.blocked({
        decision,
        trigger:  trigger ?? 'unknown',
        project:  projectDir,
        tool:     event.tool_name,
        command:  isBash ? (command.slice(0, 500) || null) : null,
        file:     isBash ? null : (getTargetPath(event) ?? null),
      });
    }
    const payload = JSON.stringify(output) + '\n';
    process.stdout.write(payload);
  }

  const rawConfig = loadConfig(projectDir);
  const config    = rawConfig ?? {};
  log.debug(rawConfig === null ? 'No guardrails.json - using built-in defaults' : 'guardrails.json loaded');

  // Load secrets early to redact command in all subsequent log lines.
  const secrets  = loadSecrets(projectDir, config, { onWarn: (m) => log.warn(m), onInfo: (m) => log.info(m) });
  const leaked   = isBash ? findLeakedSecret(command, secrets) : null;
  const cmdForLog = isBash ? (leaked ? '<redacted - possible secret>' : command.slice(0, 120)) : null;
  log.debug(`PreToolUse ${event.tool_name} | cwd=${projectDir} | ${isBash ? `cmd=${cmdForLog}` : `file=${getTargetPath(event)}`}`);

  // Resolve all target paths to absolute using projectDir as base.
  const targetPaths = (isBash
    ? extractBashWritePaths(command, projectDir)
    : getTargetPaths(event).map(expandTilde).map(fromGitBash)
  ).map((p) => path.isAbsolute(p) ? p : path.join(projectDir, p));

  // ---------------------------------------------------------------------------
  // Run all checkers - collect every match, then resolve once.
  // ---------------------------------------------------------------------------
  const allMatches = [];

  // Path-based rules (all tools)
  for (const checker of [
    checkCrossHomeWrite(targetPaths, config, projectDir),
    checkGuardrailsConfigWrite(targetPaths, config, event, projectDir),
    checkFleetConfigWrite(targetPaths, config, event, projectDir),
    checkSettingsWrite(targetPaths, config, projectDir),
    checkMemoryWrite(targetPaths, config, projectDir),
    checkSecretsFileWrite(targetPaths, config, projectDir),
    checkProtectedFiles(targetPaths, config, projectDir),
  ]) {
    if (checker) {
      log.info(`${checker.name}: ${checker.decision}`);
      allMatches.push(checker);
    }
  }

  // Bash-only rules
  if (isBash) {
    // secrets-not-gitignored must be evaluated but its deny dominates everything -
    // it participates in the accumulator like any other match.
    if (leaked) log.warn(`Secret leak detected: key=${leaked.key} | cmd=<redacted>`);

    for (const checker of [
      checkSecretsNotGitignored(config, projectDir),
      checkSecretsLeak(leaked, config),
      checkSecretsFileAccess(command, config, projectDir),
      ...checkCategories(command, config),
    ]) {
      if (checker) {
        // Log unknown decision values for category matches
        if (checker._rawDecision !== undefined && checker._rawDecision !== checker.decision) {
          log.warn(`Unknown decision value '${checker._rawDecision}' for '${checker.name}' - falling back to '${checker._defaultDecision}'`);
        }
        log.info(`${checker.name}: ${checker.decision}`);
        allMatches.push(checker);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Single resolution point
  // ---------------------------------------------------------------------------
  if (allMatches.length > 1) {
    log.info(`All triggered: ${allMatches.map(m => `${m.name}:${m.decision}`).join(', ')}`);
  }

  const label = isBash ? command : (getTargetPath(event) ?? '');
  const { worstDecision, worstMatch, askMatches } = resolveMatches(allMatches);

  if (worstMatch && worstDecision === 'deny') {
    // For category matches the message is just the description; prepend the command.
    // For all other matches the message is already self-contained.
    const msg = worstMatch._rawDecision !== undefined
      ? `[guardrails] ${worstMatch.message}\n\nCommand: ${command}`
      : worstMatch.message;
    decide('deny', msg, worstMatch.name);
    process.stdout.write('', () => process.exit(0));
    return;
  }

  if (worstMatch && worstDecision === 'ask') {
    const msg = askMatches.length >= 2
      ? buildMultiAskMessage(askMatches, label)
      : buildSingleAskMessage(worstMatch, label);
    decide('ask', msg, worstMatch.name);
    process.stdout.write('', () => process.exit(0));
    return;
  }

  log.debug('No guardrail triggered - allowing');
  process.exit(0);
}

main().catch((e) => {
  // Two-mode fail-safe:
  // - BEFORE the security logic begins (require errors, malformed stdin):
  //   fail OPEN. A bug here can lock the user out of every tool in every
  //   Claude Code session - happened on 2026-06-21 when a stale cache lacked
  //   isWriteCapableTool and every Bash/Edit/Write call became deny.
  //   An attacker cannot influence import-time errors.
  // - AFTER inSecurityLogic = true (inside checkers, accumulator, decide):
  //   fail CLOSED. A crash inside the checker could be triggered by attacker-
  //   controlled config, so we must deny.
  try { log.error(`Unexpected error: ${e.stack || e.message}`); } catch (_) {}
  if (!inSecurityLogic) {
    process.exit(0);
    return;
  }
  const reason = `[guardrails] INTERNAL ERROR - fail-safe deny\n\nThe guardrail hook crashed while evaluating this tool call:\n  ${e.message}\n\nThis is a bug. Please report it. The action has been blocked as a precaution.`;
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  }) + '\n';
  try { log.blocked && log.blocked({ decision: 'deny', trigger: 'internal-error', project: process.cwd(), tool: 'unknown', command: null, file: null }); } catch (_) {}
  try {
    process.stdout.write(output, () => process.exit(0));
  } catch (_) {
    process.exit(0);
  }
});
