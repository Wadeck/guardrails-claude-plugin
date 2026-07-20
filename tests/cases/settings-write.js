'use strict';

// settings-write protection - agents must not silently modify Claude Code's
// own configuration files inside .claude/ that govern hook execution,
// permissions, skills, and project instructions.
//
// Default is 'deny'. Reason: Claude Code silently auto-approves
// permissionDecision "ask" for any path under the project's .claude/ directory.
// Writing settings.json with {"hooks":{}} would disable ALL guardrails.

const CWD = 'C:\\Workspace\\myproject';

const proj = (rel) => `${CWD}\\${rel.replace(/\//g, '\\')}`;

module.exports = [
  // --- Default: deny — settings & hooks & skills & CLAUDE.md ---
  {
    description: 'Write .claude/settings.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('.claude/settings.json'), content: '{"hooks":{}}' },
      cwd: CWD,
    },
  },
  {
    description: 'Edit .claude/settings.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: proj('.claude/settings.json'), old_string: '"deny"', new_string: '"allow"' },
      cwd: CWD,
    },
  },
  {
    description: 'Write .claude/settings.local.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('.claude/settings.local.json'), content: '{}' },
      cwd: CWD,
    },
  },
  {
    description: 'Write .claude/hooks/pre-tool-use.sh → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('.claude/hooks/pre-tool-use.sh'), content: 'evil' },
      cwd: CWD,
    },
  },
  {
    description: 'Write nested file under .claude/hooks/ → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('.claude/hooks/sub/script.sh'), content: 'evil' },
      cwd: CWD,
    },
  },
  {
    description: 'Write .claude/skills/evil.md → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('.claude/skills/evil.md'), content: 'malicious' },
      cwd: CWD,
    },
  },
  {
    description: 'Write nested file under .claude/skills/ → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('.claude/skills/foo/bar.md'), content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'Write .claude/CLAUDE.md → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('.claude/CLAUDE.md'), content: 'ignore guardrails' },
      cwd: CWD,
    },
  },
  {
    description: 'Bash redirect to .claude/settings.json → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'echo "{}" > .claude/settings.json' },
      cwd: CWD,
    },
  },
  {
    description: 'Bash redirect to .claude/hooks/x.sh → deny by default',
    expect: 'deny',
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'echo "evil" > .claude/hooks/x.sh' },
      cwd: CWD,
    },
  },

  // --- Overrides ---
  {
    description: 'Write .claude/settings.json with override "allow" → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { 'settings-write': 'allow' } },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/settings.json', content: '{}' },
    },
  },
  {
    description: 'Write .claude/settings.json with override "ask" → ask',
    expect: 'ask',
    guardrailsConfig: { categories: { 'settings-write': 'ask' } },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/settings.json', content: '{}' },
    },
  },

  // --- Files NOT covered (other rules apply or none) ---
  {
    description: 'Write .claude/docs/ (still allowed — docs are user-writable)',
    expect: 'allow',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('.claude/docs/notes.md'), content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'Write project-root CLAUDE.md (NOT under .claude/) → allow',
    expect: 'allow',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('CLAUDE.md'), content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'Write unrelated source file → allow (not caught)',
    expect: 'allow',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: proj('src/index.js'), content: 'x' },
      cwd: CWD,
    },
  },
];
