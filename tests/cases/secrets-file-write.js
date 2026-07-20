'use strict';

// secrets-file-write protection - agents must not overwrite the configured
// secrets file (clearing the leak-detection registry).
//
// Default is 'deny'. Reason: Claude Code silently auto-approves
// permissionDecision "ask" for any path under the project's .claude/ directory
// (validated 2026-06-21). The default secrets path is .claude/guardrails.secrets,
// so 'ask' provides no real protection here.

const CWD = 'C:\\Workspace\\myproject';

const baseConfig = (extra) => ({
  secrets: { file: '.claude/guardrails.secrets' },
  ...(extra || {}),
});

module.exports = [
  // --- Default: deny ---
  {
    description: 'Write .claude/guardrails.secrets (relative) → deny by default',
    expect: 'deny',
    guardrailsConfig: baseConfig(),
    extraFiles: { '.gitignore': '.claude/guardrails.secrets\n' },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/guardrails.secrets', content: '' },
    },
  },
  {
    description: 'Edit .claude/guardrails.secrets → deny by default',
    expect: 'deny',
    guardrailsConfig: baseConfig(),
    extraFiles: { '.gitignore': '.claude/guardrails.secrets\n' },
    event: {
      tool_name: 'Edit',
      tool_input: {
        file_path: '.claude/guardrails.secrets',
        old_string: 'TOKEN=abc',
        new_string: '',
      },
    },
  },
  {
    description: 'Bash redirect overwrite secrets file → deny by default',
    expect: 'deny',
    guardrailsConfig: baseConfig(),
    extraFiles: { '.gitignore': '.claude/guardrails.secrets\n' },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'echo "" > .claude/guardrails.secrets' },
    },
  },

  // --- Overrides ---
  {
    description: 'Write secrets file with override "allow" → allow',
    expect: 'allow',
    guardrailsConfig: baseConfig({ categories: { 'secrets-file-write': 'allow' } }),
    extraFiles: { '.gitignore': '.claude/guardrails.secrets\n' },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/guardrails.secrets', content: '' },
    },
  },
  {
    description: 'Write secrets file with override "ask" → ask',
    expect: 'ask',
    guardrailsConfig: baseConfig({ categories: { 'secrets-file-write': 'ask' } }),
    extraFiles: { '.gitignore': '.claude/guardrails.secrets\n' },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/guardrails.secrets', content: '' },
    },
  },
];
