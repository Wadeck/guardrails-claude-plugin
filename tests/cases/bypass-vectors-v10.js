'use strict';

// V10 audit bypass vectors.

const CWD = 'C:\\Workspace\\myproject';
function bash(command) { return { tool_name: 'Bash', tool_input: { command }, cwd: CWD }; }

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V10-01: echo | tee | sh — tee interposed between echo and shell.
  // Pattern requires shell immediately after first pipe; tee breaks this.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V10-01a: echo "rm -rf .claude/" | tee /tmp/s.sh | sh → deny',
    expect: 'deny',
    event: bash('echo "rm -rf .claude/" | tee /tmp/s.sh | sh'),
  },
  {
    description: 'BV-V10-01b: echo "git stash" | tee /tmp/s.sh | bash → deny',
    expect: 'deny',
    event: bash('echo "git stash" | tee /tmp/s.sh | bash'),
  },

  // -------------------------------------------------------------------------
  // BV-V10-02: git filter-branch / git filter-repo — history rewrite.
  // More destructive than git reset; zero category coverage.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V10-02a: git filter-branch --env-filter HEAD → deny',
    expect: 'deny',
    event: bash("git filter-branch --env-filter '' HEAD"),
  },
  {
    description: 'BV-V10-02b: git filter-repo --drop-all-tags → deny',
    expect: 'deny',
    event: bash('git filter-repo --drop-all-tags'),
  },

  // -------------------------------------------------------------------------
  // BV-V10-03: > >(tee .claude/settings.json) output process substitution.
  // tee extractor captures ".claude/settings.json)" with trailing )
  // → normPath mismatch → path check misses.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V10-03a: echo x > >(tee .claude/settings.json) → deny',
    expect: 'deny',
    event: bash('echo x > >(tee .claude/settings.json)'),
  },
  {
    description: 'BV-V10-03b: cat evil.json > >(tee .claude/guardrails.json) → deny',
    expect: 'deny',
    event: bash('cat evil.json > >(tee .claude/guardrails.json)'),
  },

  // -------------------------------------------------------------------------
  // BV-V10-04: git push -fv / -fn / -fq — combined short flags bypass -f detection.
  // Pattern: -f(?:\s|$) doesn't match -fv (f followed by letter, not space/EOL).
  // -------------------------------------------------------------------------
  {
    description: 'BV-V10-04a: git push -fv origin main → deny (force+verbose)',
    expect: 'deny',
    event: bash('git push -fv origin main'),
  },
  {
    description: 'BV-V10-04b: git push -fn origin main → deny (force+dry-run)',
    expect: 'deny',
    event: bash('git push -fn origin main'),
  },
  {
    description: 'BV-V10-04c: git push -fq origin main → deny (force+quiet)',
    expect: 'deny',
    event: bash('git push -fq origin main'),
  },

  // -------------------------------------------------------------------------
  // BV-V10-05: declare -x / typeset -x bypass env-hijack.
  // Equivalent to export LD_PRELOAD= but uses different keyword.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V10-05a: declare -x LD_PRELOAD=/tmp/evil.so → deny',
    expect: 'deny',
    event: bash('declare -x LD_PRELOAD=/tmp/evil.so'),
  },
  {
    description: 'BV-V10-05b: typeset -x LD_PRELOAD=/tmp/evil.so → deny',
    expect: 'deny',
    event: bash('typeset -x LD_PRELOAD=/tmp/evil.so'),
  },
  {
    description: 'BV-V10-05c: declare -x LD_LIBRARY_PATH=/tmp/evil → deny',
    expect: 'deny',
    event: bash('declare -x LD_LIBRARY_PATH=/tmp/evil'),
  },

  // -------------------------------------------------------------------------
  // BV-V10-06: export PATH=.:$PATH and /dev/shm/ injection bypasses PATH pattern.
  // Current pattern only matches /tmp in the new PATH value.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V10-06a: export PATH=.:$PATH → deny (CWD PATH injection)',
    expect: 'deny',
    event: bash('export PATH=.:$PATH'),
  },
  {
    description: 'BV-V10-06b: export PATH=/dev/shm/evil:$PATH → deny',
    expect: 'deny',
    event: bash('export PATH=/dev/shm/evil:$PATH'),
  },
  {
    description: 'BV-V10-06c: export PATH=/tmp/evil:$PATH → deny (existing, verify)',
    expect: 'deny',
    event: bash('export PATH=/tmp/evil:$PATH'),
  },

  // -------------------------------------------------------------------------
  // BV-V10-07: MCP tools with unlisted write verbs (export, generate, store, dump).
  // -------------------------------------------------------------------------
  {
    description: 'BV-V10-07a: mcp__config__export_settings targeting .claude/settings.json → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__config__export_settings',
      tool_input: { path: `${CWD}\\.claude\\settings.json`, content: '{}' },
      cwd: CWD,
    },
  },
  {
    description: 'BV-V10-07b: mcp__codegen__generate_file targeting .claude/hooks/evil.sh → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__codegen__generate_file',
      tool_input: { path: `${CWD}\\.claude\\hooks\\evil.sh`, content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'BV-V10-07c: mcp__kv__store_file targeting .claude/memory/x.md → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__kv__store_file',
      tool_input: { path: `${CWD}\\.claude\\memory\\x.md`, content: 'x' },
      cwd: CWD,
    },
  },

  // -------------------------------------------------------------------------
  // BV-V10-08: kill -TERM / -SIGTERM — signal-name forms not matched.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V10-08a: kill -TERM 1234 → ask (signal-name form)',
    expect: 'ask',
    event: bash('kill -TERM 1234'),
  },
  {
    description: 'BV-V10-08b: kill -KILL 1234 → ask',
    expect: 'ask',
    event: bash('kill -KILL 1234'),
  },
  {
    description: 'BV-V10-08c: kill -SIGTERM 1234 → ask',
    expect: 'ask',
    event: bash('kill -SIGTERM 1234'),
  },
];
