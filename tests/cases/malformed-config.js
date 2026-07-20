'use strict';

// Defense-in-depth: a malformed guardrails.json must NEVER produce a silent
// "allow". Bad values (non-strings, unknown strings, weird casing) must fall
// back to the built-in default decision - and any thrown exception inside a
// checker must end with deny, not exit 0 with empty stdout.
//
// Why this matters: an attacker who can write guardrails.json could craft
// values that crash the checker on .toLowerCase() and the empty stdout would
// be interpreted by Claude Code as "allow". The previous behavior was to
// exit 0 silently on uncaught exceptions - a guard-disabling bypass.

const CWD = 'C:\\Workspace\\myproject';

module.exports = [
  // --- Numeric value: must fall back to default (rm default = deny) ---
  {
    description: 'rm category set to 0 (number) → fallback to default deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: 0 } },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /tmp/important' },
    },
  },
  {
    description: 'rm category set to 1 (number) → fallback to default deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: 1 } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },
  {
    description: 'rm category set to true (boolean) → fallback to default deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: true } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },
  {
    description: 'rm category set to false (boolean) → fallback to default deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: false } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },
  {
    description: 'rm category set to null → fallback to default deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: null } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },
  {
    description: 'rm category set to {} (object) → fallback to default deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: {} } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },
  {
    description: 'rm category set to [] (array) → fallback to default deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: [] } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },

  // --- memory-write defaults to deny - same fallback ---
  {
    description: 'memory-write set to 42 (number) → fallback deny (memory default)',
    expect: 'deny',
    guardrailsConfig: { categories: { 'memory-write': 42 } },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/memory/x.md', content: 'x' },
    },
  },

  // --- Whitespace / case variants ---
  {
    description: 'rm category set to "DENY" (uppercase) → resolves to deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: 'DENY' } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },
  {
    description: 'rm category set to " deny " (whitespace) → fallback deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: ' deny ' } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },

  // --- Unknown string: fallback ---
  {
    description: 'rm category set to "maybe" (unknown) → fallback default deny',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: 'maybe' } },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },

  // --- Categories block itself non-object: must not crash ---
  {
    description: 'categories set to null → built-in defaults still apply',
    expect: 'deny',
    guardrailsConfig: { categories: null },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },
  {
    description: 'categories set to "hello" (string) → built-in defaults still apply',
    expect: 'deny',
    guardrailsConfig: { categories: 'hello' },
    event: { tool_name: 'Bash', tool_input: { command: 'rm /tmp/x' } },
  },
];
