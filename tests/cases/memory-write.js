'use strict';

// memory-write protection: agents must not silently write into .claude/memory/.
//
// Default is 'deny'. Reason: Claude Code silently auto-approves
// permissionDecision: "ask" for any path under the project's .claude/ directory
// (no PermissionRequest event is emitted). Validated empirically 2026-06-21.
// Therefore 'ask' provides no protection in this scope — only 'deny' does.
// Projects can override to 'ask' or 'allow' explicitly in guardrails.json.

const os   = require('os');
const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();

const OUTSIDE_CWD = 'C:\\Workspace\\myproject';

module.exports = [
  // --- deny (default) ---
  {
    description: 'Write to .claude/memory/ in project → deny (default)',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'C:\\Workspace\\myproject\\.claude\\memory\\feedback.md', content: 'x' },
      cwd: OUTSIDE_CWD,
    },
  },
  {
    description: 'Edit .claude/memory/MEMORY.md in project → deny (default)',
    expect: 'deny',
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: 'C:\\Workspace\\myproject\\.claude\\memory\\MEMORY.md', old_string: 'a', new_string: 'b' },
      cwd: OUTSIDE_CWD,
    },
  },
  {
    description: 'Write to .claude/memory/ via Unix slash → deny (default)',
    expect: 'deny',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'C:/Workspace/myproject/.claude/memory/user.md', content: 'x' },
      cwd: OUTSIDE_CWD,
    },
  },

  // --- ask override (still useful when user explicitly opts in) ---
  // NOTE: guardrailsConfig causes harness to use a tmpDir as cwd.
  // Use a relative file_path so it resolves to tmpDir/.claude/memory/feedback.md.
  {
    description: 'Write to .claude/memory/ with memory-write=ask → ask',
    expect: 'ask',
    guardrailsConfig: { categories: { 'memory-write': 'ask' } },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/memory/feedback.md', content: 'x' },
    },
  },

  // --- allow override ---
  {
    description: 'Write to .claude/memory/ with memory-write=allow → allow',
    expect: 'allow',
    guardrailsConfig: { categories: { 'memory-write': 'allow' } },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/memory/feedback.md', content: 'x' },
    },
  },

  // --- deny reason message ---
  {
    description: 'deny reason mentions memory directory',
    expect: 'deny',
    expectReasonIncludes: 'memory',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'C:\\Workspace\\myproject\\.claude\\memory\\feedback.md', content: 'x' },
      cwd: OUTSIDE_CWD,
    },
  },
  {
    description: 'deny reason mentions preferred location .claude/docs/',
    expect: 'deny',
    expectReasonIncludes: '.claude/docs/',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'C:\\Workspace\\myproject\\.claude\\memory\\feedback.md', content: 'x' },
      cwd: OUTSIDE_CWD,
    },
  },

  // --- not triggered for .claude/docs/ ---
  {
    description: 'Write to .claude/docs/ (preferred location) → allow',
    expect: 'allow',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'C:\\Workspace\\myproject\\.claude\\docs\\notes.md', content: 'x' },
      cwd: OUTSIDE_CWD,
    },
  },

  // --- cross-home-write takes priority when target is in HOME ---
  {
    description: 'Write to HOME/.claude/projects/.../memory/ → deny (cross-home-write, not memory-write)',
    expect: 'deny',
    expectReasonIncludes: 'CROSS-HOME',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: { file_path: `${home}\\.claude\\projects\\my-proj\\memory\\feedback.md`, content: 'x' },
      cwd: OUTSIDE_CWD,
    }),
  },

  // --- project inside HOME/.claude: cross-home-write is skipped, memory-write still applies ---
  {
    description: 'Write to .claude/memory/ when project is inside HOME/.claude → deny (memory-write default)',
    expect: 'deny',
    event: (home) => ({
      tool_name: 'Write',
      tool_input: {
        file_path: `${home}\\.claude\\plugins\\local-marketplace\\.claude\\memory\\feedback.md`,
        content: 'x',
      },
      cwd: `${home}\\.claude\\plugins\\local-marketplace`,
    }),
  },
];
