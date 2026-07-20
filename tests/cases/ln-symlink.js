'use strict';

// ln -s creates symlinks. An attacker can plant a symlink inside .claude/
// pointing outside, then write through the symlink to bypass path-prefix
// checks (safeRealpath resolves the symlink before comparison).
//
// Default: deny. The user can opt back to ask/allow if needed.

const CWD = 'C:\\Workspace\\myproject';
const bash = (command) => ({ tool_name: 'Bash', tool_input: { command }, cwd: CWD });

module.exports = [
  // --- Default deny ---
  {
    description: 'ln -s /etc/passwd .claude/hooks/evil → deny by default',
    expect: 'deny',
    event: bash('ln -s /etc/passwd .claude/hooks/evil'),
  },
  {
    description: 'ln --symbolic /usr/bin/sh .claude/skills/x → deny',
    expect: 'deny',
    event: bash('ln --symbolic /usr/bin/sh .claude/skills/x'),
  },
  {
    description: 'ln -sf /etc/shadow .claude/random/x → deny',
    expect: 'deny',
    event: bash('ln -sf /etc/shadow .claude/random/x'),
  },
  {
    description: 'ln -s anywhere → deny by default (not just .claude/)',
    expect: 'deny',
    event: bash('ln -s /etc/passwd /tmp/evil-link'),
  },
  {
    description: 'mklink /h C:\\Windows\\... C:\\foo → deny (Windows hard-link)',
    expect: 'deny',
    event: bash('mklink /h C:\\foo C:\\Windows\\System32\\cmd.exe'),
  },
  {
    description: 'mklink /d C:\\link C:\\target → deny (Windows directory junction)',
    expect: 'deny',
    event: bash('mklink /d C:\\link C:\\target'),
  },

  // --- Hard-links variant of ln (no -s) - same risk in some scenarios ---
  {
    description: 'ln /etc/passwd .claude/hooks/x → deny (hard link)',
    expect: 'deny',
    event: bash('ln /etc/passwd .claude/hooks/x'),
  },

  // --- sudo ln - must still be caught (audit v4 HIGH) ---
  {
    description: 'sudo ln -s /etc/passwd .claude/hooks/evil → deny',
    expect: 'deny',
    event: bash('sudo ln -s /etc/passwd .claude/hooks/evil'),
  },
  {
    description: 'sudo ln -sf /tmp/evil .claude/skills/inject → deny',
    expect: 'deny',
    event: bash('sudo ln -sf /tmp/evil .claude/skills/inject'),
  },

  // --- PowerShell New-Item -Type alias (audit v4 HIGH) ---
  {
    description: 'New-Item -Type SymbolicLink → deny (PowerShell -Type alias)',
    expect: 'deny',
    event: bash('New-Item -Path .claude/hooks/evil -Type SymbolicLink -Value C:\\Windows\\System32\\cmd.exe'),
  },
  {
    description: 'New-Item -Type HardLink → deny',
    expect: 'deny',
    event: bash('New-Item -Type HardLink -Path .claude/memory/x.md -Value C:\\secret'),
  },
  {
    description: 'New-Item -Type Junction → deny',
    expect: 'deny',
    event: bash('New-Item -Type Junction -Path C:\\link -Value C:\\target'),
  },

  // --- Overrides ---
  {
    description: 'ln -s with override "allow" → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { ln: 'allow' } },
    event: { tool_name: 'Bash', tool_input: { command: 'ln -s a b' } },
  },
  {
    description: 'ln -s with override "ask" → ask',
    expect: 'ask',
    guardrailsConfig: { categories: { ln: 'ask' } },
    event: { tool_name: 'Bash', tool_input: { command: 'ln -s a b' } },
  },

  // --- False-positive safety ---
  {
    description: 'echo "ln -s test" → allow (not a real ln invocation)',
    expect: 'allow',
    event: bash('echo "ln -s test"'),
  },
  {
    description: 'unrelated command → allow',
    expect: 'allow',
    event: bash('cat README.md'),
  },
];
