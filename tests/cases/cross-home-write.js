'use strict';

// cross-home-write protection - agent running outside HOME/.claude
// attempts to write into HOME/.claude.
//
// HOME is injected via env in run-tests.js so cases stay portable.
// Each case is a function(home) → test object.

const OUTSIDE_CWD = 'C:\\Workspace\\myproject';

module.exports = [
  // --- Write tool: Windows-style absolute path ---
  {
    description: 'Write to HOME/.claude (Windows abs path) → deny',
    expect: 'deny',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `${home}\\.claude\\skills\\evil.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },

  // --- Write tool: tilde path ~\.claude ---
  {
    description: 'Write to ~\\.claude (tilde backslash) → deny',
    expect: 'deny',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `~\\.claude\\skills\\evil.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },

  // --- Write tool: tilde path ~/.claude (Unix slash) ---
  {
    description: 'Write to ~/.claude (tilde slash) → deny',
    expect: 'deny',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `~/.claude/skills/evil.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },

  // --- Write tool: git-bash path /c/Users/... ---
  {
    description: 'Write to git-bash /c/Users/.../.claude → deny',
    expect: 'deny',
    event: (home) => {
      // Convert "C:\Users\Wadeck" → "/c/Users/Wadeck"
      const gitBash = home.replace(/\\/g, '/').replace(/^([A-Z]):/, (_, d) => '/' + d.toLowerCase());
      return {
        tool_name: 'Write',
        tool_input: { file_path: `${gitBash}/.claude/skills/evil.md`, content: 'x' },
        cwd: OUTSIDE_CWD,
      };
    },
  },

  // --- Bash mv: git-bash path → deny ---
  {
    description: 'mv into git-bash HOME/.claude → deny',
    expect: 'deny',
    event: (home) => {
      const gitBash = home.replace(/\\/g, '/').replace(/^([A-Z]):/, (_, d) => '/' + d.toLowerCase());
      return {
        tool_name: 'Bash',
        tool_input: { command: `mv /tmp/evil.md ${gitBash}/.claude/skills/evil.md` },
        cwd: OUTSIDE_CWD,
      };
    },
  },

  // --- Bash cp: tilde destination → deny ---
  {
    description: 'cp into ~/.claude (tilde) → deny',
    expect: 'deny',
    event: () => ({
      tool_name: 'Bash',
      tool_input: { command: `cp /tmp/evil.md ~/.claude/skills/evil.md` },
      cwd: OUTSIDE_CWD,
    }),
  },

  // --- Write INSIDE HOME/.claude project (should be allowed) ---
  {
    description: 'Write inside HOME/.claude project (allowed) → allow',
    expect: 'allow',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `${home}\\.claude\\plugins\\myplugin\\script.js`, content: 'x' },
      cwd: `${home}\\.claude\\plugins\\myplugin`,
    }),
  },

  // --- cross-home-write explicitly set to allow in config ---
  {
    description: 'Write to HOME/.claude with cross-home-write=allow → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { 'cross-home-write': 'allow' } },
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `${home}\\.claude\\skills\\allowed.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },

  // --- Memory path writes: should deny with project-redirect message ---
  {
    description: 'Write to HOME/.claude/projects/<slug>/memory/foo.md → deny (memory redirect)',
    expect: 'deny',
    expectReasonIncludes: '.claude/memory/',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `${home}\\.claude\\projects\\C--Workspace-myproject\\memory\\user_role.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },
  {
    description: 'Write to HOME/.claude/projects/<slug>/memory/MEMORY.md → deny (memory redirect)',
    expect: 'deny',
    expectReasonIncludes: '.claude/memory/',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `${home}\\.claude\\projects\\C--Workspace-myproject\\memory\\MEMORY.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },
  {
    description: 'Write to HOME/.claude/projects/<slug>/memory/ (tilde) → deny (memory redirect)',
    expect: 'deny',
    expectReasonIncludes: '.claude/memory/',
    event: () => ({
      tool_name: 'Write',
      tool_input: { file_path: `~/.claude/projects/C--Workspace-myproject/memory/feedback_testing.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },
  {
    description: 'Write to HOME/.claude with cross-home-write=allow still allows memory path → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { 'cross-home-write': 'allow' } },
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `${home}\\.claude\\projects\\C--Workspace-myproject\\memory\\user_role.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },
];
