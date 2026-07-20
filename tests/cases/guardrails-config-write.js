'use strict';

// guardrails-config-write protection - agents proposing guardrails config changes
// must be blocked by default.
//
// Default is 'deny'. Reason: Claude Code silently auto-approves
// permissionDecision "ask" for any path under the project's .claude/ directory
// (validated 2026-06-21). Therefore 'ask' provides no real protection here —
// only 'deny' does. Users can override to 'ask' or 'allow' in guardrails.json.

const CWD = 'C:\\Workspace\\myproject';

module.exports = [
  // --- Default behaviour: 'deny' ---

  {
    description: 'Edit .claude/guardrails.json (absolute path) → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Edit',
      tool_input: {
        file_path: `${CWD}\\.claude\\guardrails.json`,
        old_string: '"git-push": "deny"',
        new_string: '"git-push": "allow"',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Write to .claude/guardrails.json (absolute path) → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: `${CWD}\\.claude\\guardrails.json`,
        content: '{"categories":{}}',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Write to .claude/guardrails.json (relative path) → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude\\guardrails.json',
        content: '{"categories":{}}',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Bash redirect echo to .claude/guardrails.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Bash',
      tool_input: { command: "echo '{\"categories\":{}}' > .claude/guardrails.json" },
      cwd: CWD,
    },
  },

  // --- Explicit ask override (still works for users who want a prompt outside .claude/) ---

  {
    description: 'Write .claude/guardrails.json with override "ask" → ask',
    expect: 'ask',
    guardrailsConfig: { categories: { 'guardrails-config-write': 'ask' } },
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/guardrails.json',
        content: '{"categories":{}}',
      },
      cwd: CWD,
    },
  },

  // --- Config overrides ---
  // These use a relative file_path so the harness-injected tmpDir is used as cwd
  // and path resolution still matches the guardrails.json check.

  {
    description: 'Write .claude/guardrails.json with override "allow" → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { 'guardrails-config-write': 'allow' } },
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/guardrails.json',
        content: '{"categories":{}}',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Write .claude/guardrails.json with override "deny" → deny',
    expect: 'deny',
    guardrailsConfig: { categories: { 'guardrails-config-write': 'deny' } },
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/guardrails.json',
        content: '{"categories":{}}',
      },
      cwd: CWD,
    },
  },

  // --- Unrelated file: must NOT be caught ---

  {
    description: 'Edit an unrelated file → allow (not caught by this rule)',
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

  // ---------------------------------------------------------------------------
  // .claude/memory/ write protection
  // Default: 'ask' — prefer .claude/docs/ + CLAUDE.md reference instead
  // ---------------------------------------------------------------------------

  {
    description: 'Write to .claude/memory/some-fact.md → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: `${CWD}\\.claude\\memory\\some-fact.md`,
        content: '# fact',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Edit file inside .claude/memory/ → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Edit',
      tool_input: {
        file_path: `${CWD}\\.claude\\memory\\MEMORY.md`,
        old_string: 'old',
        new_string: 'new',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Bash redirect to .claude/memory/ file → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'echo "fact" > .claude/memory/note.md' },
      cwd: CWD,
    },
  },

  {
    description: 'Write to .claude/memory/ with override "allow" → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { 'memory-write': 'allow' } },
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/memory/note.md',
        content: '# note',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Write to .claude/memory/ with override "deny" → deny',
    expect: 'deny',
    guardrailsConfig: { categories: { 'memory-write': 'deny' } },
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/memory/note.md',
        content: '# note',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Write to .claude/docs/ (not memory) → allow (not caught)',
    expect: 'allow',
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: `${CWD}\\.claude\\docs\\design.md`,
        content: '# design',
      },
      cwd: CWD,
    },
  },

  // ---------------------------------------------------------------------------
  // fleet-config-write protection (default: 'deny' — see fleet-config-write.js)
  // ---------------------------------------------------------------------------

  {
    description: 'Edit .claude/w-fleet.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Edit',
      tool_input: {
        file_path: `${CWD}\\.claude\\w-fleet.json`,
        old_string: '"integration"',
        new_string: '"staging"',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Write to .claude/w-fleet.json (relative path) → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/w-fleet.json',
        content: '{"protected_branches":[]}',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Bash redirect to .claude/w-fleet.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Bash',
      tool_input: { command: "echo '{\"protected_branches\":[]}' > .claude/w-fleet.json" },
      cwd: CWD,
    },
  },

  {
    description: 'Write .claude/w-fleet.json with override "allow" → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { 'fleet-config-write': 'allow' } },
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/w-fleet.json',
        content: '{"protected_branches":[]}',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Write .claude/w-fleet.json with override "deny" → deny',
    expect: 'deny',
    guardrailsConfig: { categories: { 'fleet-config-write': 'deny' } },
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: '.claude/w-fleet.json',
        content: '{"protected_branches":[]}',
      },
      cwd: CWD,
    },
  },

  {
    description: 'Write unrelated .claude/w-other.json → allow (not caught)',
    expect: 'allow',
    event: {
      tool_name: 'Write',
      tool_input: {
        file_path: `${CWD}\\.claude\\w-other.json`,
        content: '{}',
      },
      cwd: CWD,
    },
  },
];
