'use strict';

const path = require('path');
const { normPath, normPathLiteral, isDescendantOf, commandMentionsPath, collectProtectedSecretPaths } = require('./paths');
const { CATEGORIES, matchCategory } = require('./categories');
const { checkSecretsGitignored, findLeakedSecret, matchProtectedFiles } = require('./guardrails');

// All checkers return { name, description, message, decision } or null.
// checkCategories returns an array of such objects (may be empty).

const DECISION_RANK = { deny: 2, ask: 1, allow: 0 };

function resolveDecision(configCategories, name, defaultVal) {
  // Defense-in-depth: a malformed config (non-object categories, non-string
  // values) MUST NOT throw — an unhandled exception bubbles up to the hook's
  // catch handler, which exits with empty stdout, which Claude Code interprets
  // as "allow". Fall back to defaultVal for any non-string value.
  const cats = (configCategories && typeof configCategories === 'object') ? configCategories : {};
  const val = cats[name];
  if (typeof val !== 'string') return defaultVal;
  const raw = val.trim().toLowerCase();
  return (DECISION_RANK[raw] !== undefined) ? raw : defaultVal;
}

// ---------------------------------------------------------------------------
// Path-based checkers (all tools: Bash, Edit, Write, NotebookEdit)
// ---------------------------------------------------------------------------

function checkCrossHomeWrite(targetPaths, config, projectDir) {
  const HOME = process.env.USERPROFILE || process.env.HOME || '';
  const HOME_CLAUDE = HOME ? path.join(HOME, '.claude') : '';
  if (!HOME_CLAUDE || isDescendantOf(projectDir, HOME_CLAUDE)) return null;

  const homeClaudeLit = normPathLiteral(HOME_CLAUDE);

  for (const targetPath of targetPaths) {
    // Test BOTH the symlink-resolved path AND the literal path. A pre-existing
    // symlink at $HOME/.claude/x → /tmp/y would resolve outside via normPath
    // (used by isDescendantOf), but the literal form keeps the protection.
    const targetLit = normPathLiteral(targetPath, projectDir);
    const insideHome =
      isDescendantOf(targetPath, HOME_CLAUDE) ||
      targetLit === homeClaudeLit || targetLit.startsWith(homeClaudeLit + '/');
    if (!insideHome) continue;

    const decision = resolveDecision(config.categories, 'cross-home-write', 'deny');
    if (decision === 'allow') continue;

    const isMemoryPath = /[/\\]projects[/\\][^/\\]+[/\\]memory[/\\]/i.test(targetPath.replace(/\\/g, '/'));
    const projectMemoryDir = [projectDir, '.claude', 'memory'].join('/').replace(/\\/g, '/');

    let message;
    if (decision === 'deny') {
      message = isMemoryPath
        ? `[guardrails] CROSS-HOME MEMORY WRITE BLOCKED\n\nYou are trying to write a memory file outside the current project's repository:\n\n  Target (global, unversioned): ${targetPath}\n\nMemory files written there are invisible to other contributors and lost if the machine changes.\n\nInstead, write the memory file inside the CURRENT PROJECT:\n\n  Correct location: ${projectMemoryDir}/<filename>\n\nThis directory is committed with the project and visible to everyone who clones it.\nIf you meant to allow global memory writes, set "cross-home-write": "allow" in .claude/guardrails.json.`
        : `[guardrails] CROSS-HOME WRITE BLOCKED\n\nThis agent was started outside $HOME/.claude but is attempting to modify a file inside it.\n\n  Target : ${targetPath}\n  Project: ${projectDir}\n  Protected: ${HOME_CLAUDE}\n\nIf you meant to allow this, set "cross-home-write": "allow" in guardrails.json.`;
    } else {
      message = isMemoryPath
        ? `[guardrails] CROSS-HOME MEMORY WRITE - confirmation required\n\nYou are trying to write a memory file outside the current project's repository:\n\n  Target (global, unversioned): ${targetPath}\n\nMemory files written there are invisible to other contributors and lost if the machine changes.\n\nInstead, write the memory file inside the CURRENT PROJECT:\n\n  Correct location: ${projectMemoryDir}/<filename>\n\nDo you want to allow the global write anyway?`
        : `[guardrails] CROSS-HOME WRITE - confirmation required\n\nThis agent was started outside $HOME/.claude but is attempting to modify a file inside it.\n\n  Target : ${targetPath}\n  Project: ${projectDir}\n  Protected: ${HOME_CLAUDE}\n\nDo you want to allow this write?`;
    }

    return { name: 'cross-home-write', description: 'Cross-home write', message, decision };
  }
  return null;
}

function checkGuardrailsConfigWrite(targetPaths, config, event, projectDir) {
  const isBash = event.tool_name === 'Bash';
  const command = isBash ? (event?.tool_input?.command ?? '') : '';
  const guardrailsConfigPath = path.join(projectDir, '.claude', 'guardrails.json');

  const protNorm = normPath(guardrailsConfigPath);
  const protLit  = normPathLiteral(guardrailsConfigPath);

  for (const targetPath of targetPaths) {
    // Test both realpath-resolved AND literal — symlink defense.
    const targetNorm = normPath(targetPath, projectDir);
    const targetLit  = normPathLiteral(targetPath, projectDir);
    if (targetNorm !== protNorm && targetLit !== protLit) continue;

    // Default 'deny' — Claude Code silently auto-approves 'ask' for any path
    // under .claude/ (no PermissionRequest event emitted; validated 2026-06-21).
    // 'ask' offers no real protection here. See README "Notes for agents".
    const decision = resolveDecision(config.categories, 'guardrails-config-write', 'deny');
    if (decision === 'allow') continue;

    let changeDetail;
    if (isBash) {
      changeDetail = `  Command : ${command}`;
    } else if (event.tool_name === 'Edit') {
      changeDetail = `  Old     : ${(event?.tool_input?.old_string ?? '').slice(0, 200)}\n  New     : ${(event?.tool_input?.new_string ?? '').slice(0, 200)}`;
    } else if (event.tool_name === 'Write') {
      changeDetail = `  Content : ${(event?.tool_input?.content ?? '').slice(0, 200)}`;
    } else {
      changeDetail = `  File    : ${targetPath}`;
    }

    const message = decision === 'deny'
      ? [
        `[guardrails] GUARDRAILS CONFIG WRITE BLOCKED`,
        ``,
        `An agent is attempting to modify the guardrails configuration for this project.`,
        ``,
        `  File    : ${targetPath}`,
        `  Tool    : ${event.tool_name}`,
        `  Rule    : guardrails-config-write`,
        ``,
        `Agents must not self-modify their own guardrails configuration.`,
        `If you meant to allow this, set "guardrails-config-write": "allow" in guardrails.json.`,
      ].join('\n')
      : [
        `[guardrails] GUARDRAILS CONFIG WRITE - confirmation required`,
        ``,
        `An agent is proposing a change to the project guardrails configuration:`,
        ``,
        `  File    : ${targetPath}`,
        `  Tool    : ${event.tool_name}`,
        `  Rule    : guardrails-config-write`,
        changeDetail,
        ``,
        `Review the proposed change carefully before approving.`,
        `Guardrails control what actions agents are allowed to perform in this project.`,
        ``,
        `Do you want to allow this modification?`,
      ].join('\n');

    return { name: 'guardrails-config-write', description: 'Guardrails config write', message, decision };
  }
  return null;
}

function checkFleetConfigWrite(targetPaths, config, event, projectDir) {
  const isBash = event.tool_name === 'Bash';
  const command = isBash ? (event?.tool_input?.command ?? '') : '';
  const fleetConfigPath = path.join(projectDir, '.claude', 'w-fleet.json');
  const protNorm = normPath(fleetConfigPath);
  const protLit  = normPathLiteral(fleetConfigPath);

  for (const targetPath of targetPaths) {
    // Test both realpath-resolved AND literal — symlink defense.
    const targetNorm = normPath(targetPath, projectDir);
    const targetLit  = normPathLiteral(targetPath, projectDir);
    if (targetNorm !== protNorm && targetLit !== protLit) continue;

    // Default 'deny' — see checkGuardrailsConfigWrite comment.
    const decision = resolveDecision(config.categories, 'fleet-config-write', 'deny');
    if (decision === 'allow') continue;

    let changeDetail;
    if (isBash) {
      changeDetail = `  Command : ${command}`;
    } else if (event.tool_name === 'Edit') {
      changeDetail = `  Old     : ${(event?.tool_input?.old_string ?? '').slice(0, 200)}\n  New     : ${(event?.tool_input?.new_string ?? '').slice(0, 200)}`;
    } else if (event.tool_name === 'Write') {
      changeDetail = `  Content : ${(event?.tool_input?.content ?? '').slice(0, 200)}`;
    } else {
      changeDetail = `  File    : ${targetPath}`;
    }

    const message = decision === 'deny'
      ? [
        `[guardrails] FLEET CONFIG WRITE BLOCKED`,
        ``,
        `An agent is attempting to modify the w-fleet configuration for this project.`,
        ``,
        `  File    : ${targetPath}`,
        `  Tool    : ${event.tool_name}`,
        `  Rule    : fleet-config-write`,
        ``,
        `Agents must not self-modify the fleet worktree protection configuration.`,
        `If you meant to allow this, set "fleet-config-write": "allow" in guardrails.json.`,
      ].join('\n')
      : [
        `[guardrails] FLEET CONFIG WRITE - confirmation required`,
        ``,
        `An agent is proposing a change to the project fleet configuration:`,
        ``,
        `  File    : ${targetPath}`,
        `  Tool    : ${event.tool_name}`,
        `  Rule    : fleet-config-write`,
        changeDetail,
        ``,
        `Review the proposed change carefully before approving.`,
        `This file controls which branches workspace agents are forbidden from committing to.`,
        ``,
        `Do you want to allow this modification?`,
      ].join('\n');

    return { name: 'fleet-config-write', description: 'Fleet config write', message, decision };
  }
  return null;
}

function checkSettingsWrite(targetPaths, config, projectDir) {
  // Protect Claude Code's own configuration files inside .claude/.
  // Default 'deny' — Claude Code silently auto-approves 'ask' for any path
  // under .claude/ (validated 2026-06-21). Writing settings.json with
  // {"hooks":{}} would disable all hook-based guardrails. CLAUDE.md and
  // skills/ are also project-level instructions an agent must not rewrite.
  const claudeDir = path.join(projectDir, '.claude');
  const claudeNorm = normPath(claudeDir);
  const claudeNormLit = normPathLiteral(claudeDir);

  // Files (exact match) and directories (prefix match with '/') under .claude/
  // that govern Claude Code behavior. Trailing '/' marks directory prefixes.
  // All entries must be lowercase: normPath lowercases for case-insensitive
  // comparison (Windows). Without this, CLAUDE.md → claude.md never matches.
  const protectedRels = [
    'settings.json',
    'settings.local.json',
    'claude.md',
    'hooks/',
    'skills/',
    'commands/',
  ];

  for (const targetPath of targetPaths) {
    // Test BOTH the realpath-resolved form AND the literal form. A symlink at
    // .claude/hooks/x → /tmp/innocent would resolve outside .claude/ via normPath,
    // but the literal form keeps the protection. Whichever form falls inside
    // .claude/ triggers the rule.
    const candidates = [
      normPath(targetPath, projectDir),
      normPathLiteral(targetPath, projectDir),
    ];

    let matched = null;
    let isClaudeRoot = false;
    for (const norm of candidates) {
      const claudeRoot = (norm === claudeNorm) || (norm === claudeNormLit);
      const claudePrefix = norm.startsWith(claudeNorm + '/') || norm.startsWith(claudeNormLit + '/');
      if (!claudeRoot && !claudePrefix) continue;
      if (claudeRoot) {
        matched = '.claude/ (directory write — could place protected files inside)';
        isClaudeRoot = true;
        break;
      }
      const baseLen = norm.startsWith(claudeNorm + '/') ? claudeNorm.length + 1 : claudeNormLit.length + 1;
      const rel = norm.slice(baseLen);
      // Pre-compute glob prefix once for this rel (empty string if no wildcard).
      // Include `[` as a glob character (bash character-class globs like `settings[.json]`).
      const hasGlob = /[*?[]/.test(rel);
      const globPrefix = hasGlob ? rel.slice(0, rel.search(/[*?[]/)) : null;
      for (const p of protectedRels) {
        if (p.endsWith('/')) {
          if (rel === p.slice(0, -1) || rel.startsWith(p)) { matched = p; break; }
          // Shell glob: `hooks*` — glob prefix 'hooks' is a prefix of 'hooks/' → deny.
          if (hasGlob && (p.slice(0, -1).startsWith(globPrefix) || p.startsWith(globPrefix))) {
            matched = p; break;
          }
        } else if (rel === p) {
          matched = p; break;
        } else if (hasGlob) {
          // Shell glob in the path (e.g. `.claude/settings*`): if the glob
          // prefix (up to first wildcard) is a prefix of a protected entry,
          // deny conservatively — the shell may expand it to the protected file.
          if (p.startsWith(globPrefix)) { matched = p; break; }
        }
      }
      if (matched) break;
    }
    if (!matched) continue;

    const decision = resolveDecision(config.categories, 'settings-write', 'deny');
    if (decision === 'allow') continue;

    const message = decision === 'deny'
      ? [
        `[guardrails] CLAUDE CODE SETTINGS WRITE BLOCKED`,
        ``,
        `An agent is attempting to modify a Claude Code configuration file.`,
        ``,
        `  File    : ${targetPath}`,
        `  Rule    : settings-write`,
        ``,
        `Writing this file could disable hooks, override permissions, or plant`,
        `malicious skills/instructions. If you meant to allow this, set`,
        `"settings-write": "allow" in .claude/guardrails.json.`,
      ].join('\n')
      : [
        `[guardrails] CLAUDE CODE SETTINGS WRITE - confirmation required`,
        ``,
        `An agent is attempting to modify a Claude Code configuration file:`,
        ``,
        `  File    : ${targetPath}`,
        `  Rule    : settings-write`,
        ``,
        `Do you want to allow this modification?`,
      ].join('\n');

    return { name: 'settings-write', description: 'Claude Code settings write', message, decision };
  }
  return null;
}

function checkMemoryWrite(targetPaths, config, projectDir) {
  const projectMemoryDirPath = path.join(projectDir, '.claude', 'memory');
  const memNorm = normPath(projectMemoryDirPath);
  const memNormLit = normPathLiteral(projectMemoryDirPath);

  for (const targetPath of targetPaths) {
    // Test both realpath-resolved AND literal — symlink defense (see settings).
    const norm = normPath(targetPath, projectDir);
    const normLit = normPathLiteral(targetPath, projectDir);
    const inside =
      norm.startsWith(memNorm + '/') || norm === memNorm ||
      normLit.startsWith(memNormLit + '/') || normLit === memNormLit;
    if (!inside) continue;

    // Default 'deny' — Claude Code silently auto-approves 'ask' for any path
    // under .claude/ (no PermissionRequest event emitted; validated 2026-06-21),
    // so 'ask' provides zero protection in this scope. See README "Notes for agents".
    const decision = resolveDecision(config.categories, 'memory-write', 'deny');
    if (decision === 'allow') continue;

    const message = decision === 'deny'
      ? [
        `[guardrails] MEMORY DIRECTORY WRITE BLOCKED`,
        ``,
        `An agent is attempting to write to the project's .claude/memory/ directory.`,
        ``,
        `  File    : ${targetPath}`,
        `  Rule    : memory-write`,
        ``,
        `Write to .claude/docs/ instead, and add a reference in CLAUDE.md.`,
        `If you meant to allow memory writes, set "memory-write": "allow" in guardrails.json.`,
      ].join('\n')
      : [
        `[guardrails] MEMORY DIRECTORY WRITE - confirmation required`,
        ``,
        `An agent is attempting to write to the project's .claude/memory/ directory:`,
        ``,
        `  File    : ${targetPath}`,
        `  Rule    : memory-write`,
        ``,
        `The preferred location for agent-written knowledge is .claude/docs/, not .claude/memory/.`,
        `Files in .claude/docs/ should be referenced in the project's CLAUDE.md so they`,
        `are loaded into context and visible to all contributors.`,
        ``,
        `Do you want to allow this write to .claude/memory/ anyway?`,
      ].join('\n');

    return { name: 'memory-write', description: 'Memory directory write', message, decision };
  }
  return null;
}

function checkSecretsFileWrite(targetPaths, config, projectDir) {
  const protected_ = collectProtectedSecretPaths(projectDir, config);

  for (const targetPath of targetPaths) {
    // Pre-compute both forms for the target.
    const targetNorm = normPath(targetPath, projectDir);
    const targetLit  = normPathLiteral(targetPath, projectDir);
    for (const p of protected_) {
      // Symlink defense: match on either resolved or literal form.
      if (targetNorm !== normPath(p) && targetLit !== normPathLiteral(p)) continue;

      // Default 'deny' — see checkGuardrailsConfigWrite comment. Default secrets
      // path is .claude/guardrails.secrets, where 'ask' is silently auto-approved.
      const decision = resolveDecision(config.categories, 'secrets-file-write', 'deny');
      if (decision === 'allow') continue;

      const message = decision === 'deny'
        ? `[guardrails] SECRETS FILE WRITE BLOCKED\n\nAn agent is attempting to modify a secrets file for this project.\n\n  File: ${targetPath}\n  Rule: secrets-file-write\n\nOverwriting this file would disable secret leak detection for subsequent commands.\nIf you meant to allow this, set "secrets-file-write": "allow" in guardrails.json.`
        : `[guardrails] SECRETS FILE WRITE - confirmation required\n\nAn agent is attempting to modify a secrets file for this project.\n\n  File: ${targetPath}\n  Rule: secrets-file-write\n\nOverwriting this file would disable secret leak detection for subsequent commands.\nDo you want to allow this modification?`;

      return { name: 'secrets-file-write', description: 'Secrets file write', message, decision };
    }
  }
  return null;
}

function checkProtectedFiles(targetPaths, config, projectDir) {
  const rules = config.protected_files;
  if (!Array.isArray(rules) || rules.length === 0) return null;

  const projectDirNorm = normPath(projectDir);
  const projectDirLit  = normPathLiteral(projectDir);
  let worstDecision = null;
  const matchedPaths = [];
  let upgradedFromAsk = false; // tracks whether any rule was lifted ask→deny

  for (const targetPath of targetPaths) {
    // Symlink defense: derive a relPath from either the resolved form OR the
    // literal form, whichever is inside projectDir. Try resolved first.
    const absNorm = normPath(targetPath, projectDir);
    const absLit  = normPathLiteral(targetPath, projectDir);
    let relPath = null;
    if (absNorm === projectDirNorm) relPath = '';
    else if (absNorm.startsWith(projectDirNorm + '/')) relPath = absNorm.slice(projectDirNorm.length + 1);
    else if (absLit === projectDirLit) relPath = '';
    else if (absLit.startsWith(projectDirLit + '/')) relPath = absLit.slice(projectDirLit.length + 1);
    if (relPath === null) continue;

    let decision = matchProtectedFiles(rules, relPath);
    if (decision === null || decision === 'allow') continue;

    // ask is silently auto-approved by Claude Code under .claude/. Upgrade to
    // deny so the user actually gets protection. See README "Notes for agents".
    if (decision === 'ask' && (relPath === '.claude' || relPath.startsWith('.claude/'))) {
      decision = 'deny';
      upgradedFromAsk = true;
    }

    matchedPaths.push({ targetPath, relPath });
    if (worstDecision === null || DECISION_RANK[decision] > DECISION_RANK[worstDecision]) {
      worstDecision = decision;
    }
  }

  if (worstDecision === null || matchedPaths.length === 0) return null;

  const fileList = matchedPaths.map(({ relPath }) => `  ${relPath}`).join('\n');
  const message = worstDecision === 'deny'
    ? [
      `[guardrails] PROTECTED FILE WRITE BLOCKED`,
      ``,
      `An agent is attempting to write to a file protected by guardrails configuration.`,
      ``,
      `  Rule     : protected-files`,
      `  Protected file(s):\n${fileList}`,
      ``,
      `To allow this write, remove or update the matching rule in .claude/guardrails.json.`,
    ].join('\n')
    : [
      `[guardrails] PROTECTED FILE WRITE - confirmation required`,
      ``,
      `An agent is attempting to write to a file protected by guardrails configuration.`,
      ``,
      `  Rule     : protected-files`,
      `  Protected file(s):\n${fileList}`,
      ``,
      `Do you want to allow this write?`,
    ].join('\n');

  return { name: 'protected-files', description: 'Protected file write', message, decision: worstDecision };
}

// ---------------------------------------------------------------------------
// Bash-only checkers
// ---------------------------------------------------------------------------

function checkSecretsNotGitignored(config, projectDir) {
  const { gitignored, secretsRelPath } = checkSecretsGitignored(projectDir, config);
  if (!secretsRelPath || gitignored) return null;
  return {
    name: 'secrets-not-gitignored',
    description: 'Secrets file not in .gitignore',
    decision: 'deny',
    message:
      `[guardrails] SECURITY WARNING: The secrets file '${secretsRelPath}' is configured but does NOT appear in any .gitignore. ` +
      `Add it immediately to prevent accidental commits. ` +
      `Use the Edit tool to add '${secretsRelPath}' to .gitignore (Bash commands are blocked until this is fixed).`,
  };
}

function checkSecretsLeak(leaked, config) {
  if (!leaked) return null;
  const redirectMsg = config.secrets?.redirect_message
    ?? 'Do not use raw credentials in commands. Use the project CLI tooling instead.';
  return {
    name: 'secrets-leak',
    description: 'Secret value in command',
    decision: 'deny',
    message: `[guardrails] Secret '${leaked.key}' detected in command. ${redirectMsg}`,
  };
}

function checkSecretsFileAccess(command, config, projectDir) {
  const protectedPaths = collectProtectedSecretPaths(projectDir, config);
  for (const p of protectedPaths) {
    if (!commandMentionsPath(command, p, projectDir)) continue;

    const decision = resolveDecision(config.categories, 'secrets-file-access', 'deny');
    if (decision === 'allow') continue;

    const message = decision === 'deny'
      ? `[guardrails] SECRETS FILE ACCESS BLOCKED\n\nThe command references a protected secrets file:\n\n  File: ${p}\n  Rule: secrets-file-access\n\nAgents must not directly read, copy, source, or otherwise interact with secrets files.\nUse the project CLI tooling instead.`
      : `[guardrails] SECRETS FILE ACCESS - confirmation required\n\nThe command references a protected secrets file:\n\n  File: ${p}\n  Rule: secrets-file-access\n\nDo you want to allow this?`;

    return { name: 'secrets-file-access', description: 'Secrets file access', message, decision };
  }
  return null;
}

function checkCategories(command, config) {
  const matches = matchCategory(command, Object.keys(CATEGORIES));
  const results = [];
  for (const matched of matches) {
    // Defense-in-depth: same hardening as resolveDecision — non-string values
    // must not crash the checker (silent allow). Use the resolved decision as
    // the canonical _rawDecision when the configured value is unusable.
    const cats = (config.categories && typeof config.categories === 'object') ? config.categories : {};
    const cfgVal = cats[matched.name];
    const decision = resolveDecision(config.categories, matched.name, matched.defaultDecision);
    const raw = (typeof cfgVal === 'string') ? cfgVal.toLowerCase() : matched.defaultDecision;
    if (decision === 'allow') continue;
    results.push({
      name: matched.name,
      description: matched.description ?? matched.name,
      message: matched.message,
      decision,
      _rawDecision: raw,
      _defaultDecision: matched.defaultDecision,
    });
  }
  return results;
}

module.exports = {
  checkCrossHomeWrite,
  checkGuardrailsConfigWrite,
  checkFleetConfigWrite,
  checkSettingsWrite,
  checkMemoryWrite,
  checkSecretsFileWrite,
  checkProtectedFiles,
  checkSecretsNotGitignored,
  checkSecretsLeak,
  checkSecretsFileAccess,
  checkCategories,
  DECISION_RANK,
};
