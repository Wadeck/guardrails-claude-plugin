'use strict';

// V8b — findings confirmed by subprocess V8

const CWD = 'C:\\Workspace\\myproject';
function bash(command) { return { tool_name: 'Bash', tool_input: { command }, cwd: CWD }; }

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V8-04: .claude/commands/ not in checkSettingsWrite protectedRels.
  // Claude Code per-project slash commands live in .claude/commands/ — writing
  // there plants a persistent backdoor (arbitrary tool sequences in markdown).
  // -------------------------------------------------------------------------
  {
    description: 'BV-V8-04a: Write to .claude/commands/evil.md → deny',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: `${CWD}\\.claude\\commands\\evil.md`, content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'BV-V8-04b: Edit .claude/commands/existing.md → deny',
    expect: 'deny',
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: `${CWD}\\.claude\\commands\\existing.md`, old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },
  {
    description: 'BV-V8-04c: Bash echo > .claude/commands/x.md → deny',
    expect: 'deny',
    event: bash(`echo evil > .claude/commands/x.md`),
  },

  // -------------------------------------------------------------------------
  // BV-V8-09: stripEchoArgs bypass — printf/echo "dangerous" | sh erases the
  // dangerous content from the stripped command used for category matching.
  // printf "rm -rf /tmp\n" | sh → stripped = " | sh" → rm not detected.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V8-09a: printf "rm -rf /tmp\n" | sh → deny (echo-pipe-shell)',
    expect: 'deny',
    event: bash('printf "rm -rf /tmp/x\n" | sh'),
  },
  {
    description: 'BV-V8-09b: echo "git stash" | bash → deny (echo-pipe-shell)',
    expect: 'deny',
    event: bash('echo "git stash" | bash'),
  },
  {
    description: 'BV-V8-09c: echo \'git reset --hard\' | sh → deny (single-quoted)',
    expect: 'deny',
    event: bash("echo 'git reset --hard' | sh"),
  },
  {
    description: 'BV-V8-09d: echo "git push" → allow (not piped to shell)',
    expect: 'allow',
    event: bash('echo "git push origin main"'),
  },

  // -------------------------------------------------------------------------
  // BV-V8-14: source at command-position with arbitrary paths not blocked.
  // Only /tmp/, /dev/, /proc/, /sys/ are covered. ~/evil.sh and /etc/profile pass.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V8-14a: source ~/evil.sh → deny',
    expect: 'deny',
    event: bash('source ~/evil.sh'),
  },
  {
    description: 'BV-V8-14b: . ~/evil.sh → deny (dot-source)',
    expect: 'deny',
    event: bash('. ~/evil.sh'),
  },
  {
    description: 'BV-V8-14c: source /etc/profile → deny',
    expect: 'deny',
    event: bash('source /etc/profile'),
  },
  {
    description: 'BV-V8-14d: source /home/user/setup.sh → deny',
    expect: 'deny',
    event: bash('source /home/user/setup.sh'),
  },
  {
    description: 'BV-V8-14e: source .env (relative, project file) → allow',
    expect: 'allow',
    event: bash('source .env'),
  },
  {
    description: 'BV-V8-14f: source ./scripts/setup.sh (relative) → allow',
    expect: 'allow',
    event: bash('source ./scripts/setup.sh'),
  },
];
