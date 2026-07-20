'use strict';

// Symlink two-step bypass — primary defense is the ln category (deny by default).
// Secondary defense: if a Write/Edit tool targets a path that LITERALLY appears
// to be under .claude/, block it regardless of where the symlink resolves to.
// safeRealpath resolves symlinks before comparison, which can let an attacker
// place a symlink at .claude/hooks/x → /tmp/innocent and write through it.
//
// We can't actually create symlinks in unit tests cross-platform, so we test
// the path-comparison logic: a literal path containing .claude/ must be checked
// against settings-write and memory-write rules even if its real path differs.

const CWD = 'C:\\Workspace\\myproject';

module.exports = [
  // The literal path is under .claude/ — must be denied by settings-write
  // regardless of how realpath would resolve it.
  {
    description: 'Write to literal .claude/hooks/x (path checked before realpath) → deny',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: `${CWD}\\.claude\\hooks\\x.sh`, content: 'evil' },
      cwd: CWD,
    },
  },
  {
    description: 'Write to literal .claude/settings.json → deny',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/settings.json', content: '{}' },
      cwd: CWD,
    },
  },
  {
    description: 'Write to literal .claude/memory/x.md → deny (memory-write)',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/memory/x.md', content: 'x' },
      cwd: CWD,
    },
  },

  // The user has not opted in: ln category itself is deny.
  {
    description: 'ln -s /etc/passwd .claude/hooks/x.sh → deny (ln category)',
    expect: 'deny',
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'ln -s /etc/passwd .claude/hooks/x.sh' },
      cwd: CWD,
    },
  },

  // --- v5 audit: cross-home-write must also check literal path (consistency) ---
  // When project is OUTSIDE $HOME/.claude, a literal write into $HOME/.claude
  // must be denied even if a (pre-existing) symlink would resolve elsewhere.
  {
    description: 'Write literal $HOME/.claude/skills/evil.md from outside project → deny',
    expect: 'deny',
    expectReasonIncludes: 'CROSS-HOME',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `${home}\\.claude\\skills\\evil.md`, content: 'x' },
      cwd: CWD,
    }),
  },

  // --- v5 audit: secrets-file-write also dual-check ---
  {
    description: 'Write literal .claude/guardrails.secrets → deny (secrets-file-write)',
    expect: 'deny',
    guardrailsConfig: { secrets: { file: '.claude/guardrails.secrets' } },
    extraFiles: { '.gitignore': '.claude/guardrails.secrets\n' },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/guardrails.secrets', content: '' },
    },
  },

  // --- v5 audit: protected-files also dual-check ---
  {
    description: 'protected_files glob "secrets/**" matches literal path → deny',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: 'secrets/**', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'secrets/key.pem', content: 'x' },
    },
  },
];
