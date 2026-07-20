'use strict';

// fleet-config-write protection - agents must not modify .claude/w-fleet.json
// (controls fleet branch isolation) without explicit user opt-in.
//
// Default is 'deny'. Reason: Claude Code silently auto-approves
// permissionDecision "ask" for any path under the project's .claude/ directory
// (validated 2026-06-21). Therefore 'ask' provides no real protection here.

const CWD = 'C:\\Workspace\\myproject';

module.exports = [
  // --- Default: deny ---
  {
    description: 'Write .claude/w-fleet.json (abs path) → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: `${CWD}\\.claude\\w-fleet.json`,
        content: '{"protected_branches":[]}',
      },
      cwd: CWD,
    },
  },
  {
    description: 'Edit .claude/w-fleet.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Edit',
      tool_input: {
        file_path: `${CWD}\\.claude\\w-fleet.json`,
        old_string: 'main',
        new_string: 'attacker-branch',
      },
      cwd: CWD,
    },
  },
  {
    description: 'Write .claude/w-fleet.json (relative path) → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/w-fleet.json',
        content: '{}',
      },
      cwd: CWD,
    },
  },
  {
    description: 'Bash redirect to .claude/w-fleet.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'echo "{}" > .claude/w-fleet.json' },
      cwd: CWD,
    },
  },

  // --- Overrides ---
  {
    description: 'Write .claude/w-fleet.json with override "allow" → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { 'fleet-config-write': 'allow' } },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/w-fleet.json', content: '{}' },
    },
  },
  {
    description: 'Write .claude/w-fleet.json with override "ask" → ask',
    expect: 'ask',
    guardrailsConfig: { categories: { 'fleet-config-write': 'ask' } },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/w-fleet.json', content: '{}' },
    },
  },

  // --- Unrelated file: must NOT be caught ---
  {
    description: 'Edit unrelated file → not caught by fleet-config-write',
    expect: 'allow',
    event: {
      tool_name: 'Edit',
      tool_input: {
        file_path: `${CWD}\\src\\index.js`,
        old_string: 'a',
        new_string: 'b',
      },
      cwd: CWD,
    },
  },
];
