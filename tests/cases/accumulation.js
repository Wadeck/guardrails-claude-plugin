'use strict';

// Cross-rule accumulation tests.
// All rules participate in the same match pool - most restrictive wins (deny > ask),
// multiple ask-level matches appear together in the multi-ask dialog.
//
// Each case uses guardrailsConfig so the harness sets up a tmpDir as event.cwd,
// and path-based checks resolve correctly against it.

const CWD = 'C:\\Workspace\\myproject';

module.exports = [

  // ---------------------------------------------------------------------------
  // guardrails-config-write (ask) + category ask → both in dialog
  // ---------------------------------------------------------------------------
  {
    description: 'guardrails-config-write ask + category ask → ask, reason includes both',
    expect: 'ask',
    expectReasonIncludes: 'guardrails-config-write',
    guardrailsConfig: { categories: { 'guardrails-config-write': 'ask', rm: 'ask' } },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm .claude/guardrails.json' },
      cwd: CWD,
    },
  },

  {
    description: 'guardrails-config-write ask + category deny → deny wins',
    expect: 'deny',
    guardrailsConfig: { categories: { 'guardrails-config-write': 'ask', rm: 'deny' } },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm .claude/guardrails.json' },
      cwd: CWD,
    },
  },

  {
    description: 'guardrails-config-write deny + category ask → deny wins',
    expect: 'deny',
    guardrailsConfig: { categories: { 'guardrails-config-write': 'deny', rm: 'ask' } },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm .claude/guardrails.json' },
      cwd: CWD,
    },
  },

  // ---------------------------------------------------------------------------
  // memory-write (ask) + category ask → both in dialog
  // ---------------------------------------------------------------------------
  {
    description: 'memory-write ask + category ask → ask, reason includes memory-write',
    expect: 'ask',
    expectReasonIncludes: 'memory-write',
    guardrailsConfig: { categories: { 'memory-write': 'ask', rm: 'ask' } },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm .claude/memory/note.md' },
      cwd: CWD,
    },
  },

  {
    description: 'memory-write deny + category ask → deny wins',
    expect: 'deny',
    guardrailsConfig: { categories: { 'memory-write': 'deny', rm: 'ask' } },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm .claude/memory/note.md' },
      cwd: CWD,
    },
  },

  // ---------------------------------------------------------------------------
  // secrets-file-write (ask) + category ask → both in dialog
  // ---------------------------------------------------------------------------
  {
    description: 'secrets-file-write ask + category ask → ask, reason includes secrets-file-write',
    expect: 'ask',
    expectReasonIncludes: 'secrets-file-write',
    guardrailsConfig: {
      secrets: { file: '.claude/guardrails.secrets' },
      // secrets-file-access also fires on `rm .claude/guardrails.secrets` (basename match);
      // set it to ask so the test focuses on secrets-file-write vs rm accumulation.
      categories: { 'secrets-file-write': 'ask', 'secrets-file-access': 'ask', rm: 'ask' },
    },
    extraFiles: {
      '.claude/guardrails.secrets': 'MY_TOKEN=abc123xyz',
      '.gitignore': '.claude/guardrails.secrets',
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm .claude/guardrails.secrets' },
      cwd: CWD,
    },
  },

  {
    description: 'secrets-file-write deny + category ask → deny wins',
    expect: 'deny',
    guardrailsConfig: {
      secrets: { file: '.claude/guardrails.secrets' },
      categories: { 'secrets-file-write': 'deny', 'secrets-file-access': 'ask', rm: 'ask' },
    },
    extraFiles: {
      '.claude/guardrails.secrets': 'MY_TOKEN=abc123xyz',
      '.gitignore': '.claude/guardrails.secrets',
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm .claude/guardrails.secrets' },
      cwd: CWD,
    },
  },

  // ---------------------------------------------------------------------------
  // secrets-file-access (ask) + category ask → both in dialog
  // ---------------------------------------------------------------------------
  {
    description: 'secrets-file-access ask + category ask → ask, reason includes secrets-file-access',
    expect: 'ask',
    expectReasonIncludes: 'secrets-file-access',
    guardrailsConfig: {
      secrets: { file: '.claude/guardrails.secrets' },
      categories: { 'secrets-file-access': 'ask', 'git-commit': 'ask' },
    },
    extraFiles: {
      '.claude/guardrails.secrets': 'MY_TOKEN=abc123xyz',
      '.gitignore': '.claude/guardrails.secrets',
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'cat .claude/guardrails.secrets && git commit -m "test"' },
      cwd: CWD,
    },
  },

  // ---------------------------------------------------------------------------
  // protected_files (ask) + category ask → both in dialog
  // ---------------------------------------------------------------------------
  {
    description: 'protected_files ask + category ask → ask, reason includes protected-files',
    expect: 'ask',
    expectReasonIncludes: 'protected-files',
    guardrailsConfig: {
      protected_files: [{ glob: 'config/**', decision: 'ask' }],
      categories: { rm: 'ask' },
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm config/database.json' },
      cwd: CWD,
    },
  },

  {
    description: 'protected_files deny + category ask → deny wins',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [{ glob: 'config/**', decision: 'deny' }],
      categories: { rm: 'ask' },
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm config/database.json' },
      cwd: CWD,
    },
  },

  // ---------------------------------------------------------------------------
  // Non-Bash: path-based rules accumulate across tools
  // ---------------------------------------------------------------------------
  {
    description: 'Edit: guardrails-config-write ask + protected_files deny → deny wins',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [{ glob: '.claude/**', decision: 'deny' }],
      categories: { 'guardrails-config-write': 'ask' },
    },
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: '.claude/guardrails.json', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  {
    description: 'Edit: memory-write ask + protected_files ask on .claude/ → both upgraded to deny',
    // protected_files ask under .claude/ is silently auto-approved by Claude Code,
    // so we upgrade it to deny (audit v4 fix). memory-write 'ask' override is
    // honored as-is (the user explicitly opted in), but protected-files wins
    // with the upgraded deny via the accumulator.
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [{ glob: '.claude/memory/**', decision: 'ask' }],
      categories: { 'memory-write': 'ask' },
    },
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: '.claude/memory/note.md', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  // ---------------------------------------------------------------------------
  // Single-ask path-based: buildSingleAskMessage must not double-wrap
  // ---------------------------------------------------------------------------
  {
    description: 'guardrails-config-write alone at ask → reason contains [guardrails] exactly once',
    expect: 'ask',
    expectReasonIncludes: 'guardrails-config-write',
    guardrailsConfig: { categories: { 'guardrails-config-write': 'ask' } },
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: '.claude/guardrails.json', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  {
    description: 'memory-write alone at ask → reason does not double-wrap [guardrails]',
    expect: 'ask',
    expectReasonIncludes: 'MEMORY DIRECTORY WRITE',
    guardrailsConfig: { categories: { 'memory-write': 'ask' } },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/memory/note.md', content: 'x' },
      cwd: CWD,
    },
  },

  {
    description: 'protected_files alone at ask → reason does not double-wrap [guardrails]',
    expect: 'ask',
    expectReasonIncludes: 'PROTECTED FILE WRITE',
    guardrailsConfig: { protected_files: [{ glob: '**/*.pem', decision: 'ask' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'server.pem', content: 'x' },
      cwd: CWD,
    },
  },

  // ---------------------------------------------------------------------------
  // secrets-not-gitignored deny dominates all ask-level matches
  // ---------------------------------------------------------------------------
  {
    description: 'secrets-not-gitignored deny dominates category ask',
    expect: 'deny',
    expectReasonIncludes: 'gitignore',
    guardrailsConfig: {
      secrets: { file: '.claude/guardrails.secrets' },
      categories: { rm: 'ask' },
    },
    extraFiles: {
      // secrets file exists but is NOT in .gitignore
      '.claude/guardrails.secrets': 'MY_TOKEN=abc123xyz',
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm somefile.txt' },
      cwd: CWD,
    },
  },
];
