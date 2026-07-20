'use strict';

// MCP (Model Context Protocol) tools that write files MUST be intercepted.
// Anthropic's filesystem MCP exposes mcp__filesystem__write_file,
// mcp__filesystem__edit_file, etc. Without coverage, an agent can bypass
// every path-based check by using the MCP equivalent.
//
// We extract the target path from common MCP tool_input shapes (path,
// file_path, target_path) and run the same path-based checks.

const CWD = 'C:\\Workspace\\myproject';

module.exports = [
  // --- MCP filesystem write to .claude/settings.json → deny ---
  {
    description: 'mcp__filesystem__write_file targeting .claude/settings.json → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__write_file',
      tool_input: { path: `${CWD}\\.claude\\settings.json`, content: '{}' },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__filesystem__edit_file targeting .claude/hooks/x.sh → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__edit_file',
      tool_input: { path: `${CWD}\\.claude\\hooks\\x.sh`, edits: [] },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__filesystem__write_file targeting .claude/memory/x.md → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__write_file',
      tool_input: { path: `${CWD}\\.claude\\memory\\x.md`, content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__filesystem__write_file targeting .claude/guardrails.json → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__write_file',
      tool_input: { path: `${CWD}\\.claude\\guardrails.json`, content: '{}' },
      cwd: CWD,
    },
  },

  // --- file_path key (alternative MCP shape) ---
  {
    description: 'MCP tool with file_path key targeting .claude/CLAUDE.md → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__custom__write',
      tool_input: { file_path: `${CWD}\\.claude\\CLAUDE.md`, content: 'x' },
      cwd: CWD,
    },
  },

  // --- MCP write outside .claude/ → not caught by settings-write ---
  {
    description: 'MCP write to project src file → allow (no path check matches)',
    expect: 'allow',
    event: {
      tool_name: 'mcp__filesystem__write_file',
      tool_input: { path: `${CWD}\\src\\index.js`, content: 'x' },
      cwd: CWD,
    },
  },

  // --- MCP write outside HOME/.claude → cross-home-write deny ---
  {
    description: 'MCP write to ~/.claude/skills/evil → deny (cross-home-write)',
    expect: 'deny',
    expectReasonIncludes: 'CROSS-HOME',
    event: (home) => ({
      tool_name: 'mcp__filesystem__write_file',
      tool_input: { path: `${home}\\.claude\\skills\\evil.md`, content: 'x' },
      cwd: CWD,
    }),
  },

  // --- v4 audit: MCP word-list extensions ---
  {
    description: 'mcp__filesystem__atomic_replace targeting .claude/settings.json → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__atomic_replace',
      tool_input: { path: `${CWD}\\.claude\\settings.json`, content: '{}' },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__fs__truncate targeting .claude/memory/x.md → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__fs__truncate',
      tool_input: { path: `${CWD}\\.claude\\memory\\x.md` },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__filesystem__rename targeting .claude/settings.json → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__rename',
      tool_input: { path: `${CWD}\\.claude\\settings.json`, new_name: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__filesystem__insert into .claude/hooks/x → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__insert',
      tool_input: { path: `${CWD}\\.claude\\hooks\\x.sh`, content: 'evil' },
      cwd: CWD,
    },
  },

  // --- v4 audit: multi-path / src+dst shapes ---
  {
    description: 'mcp__filesystem__copy_file with destination → deny on .claude/settings.json',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__copy_file',
      tool_input: { source: 'safe.txt', destination: `${CWD}\\.claude\\settings.json` },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__filesystem__move with src+dst shape → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__move',
      tool_input: { src: 'safe.txt', dst: `${CWD}\\.claude\\hooks\\evil.sh` },
      cwd: CWD,
    },
  },

  // --- v5 audit: extended MCP verb-list ---
  {
    description: 'mcp__redis__set targeting .claude/settings.json → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__redis__set',
      tool_input: { path: `${CWD}\\.claude\\settings.json`, content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__s3__upload_file targeting .claude/hooks/x → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__s3__upload_file',
      tool_input: { path: `${CWD}\\.claude\\hooks\\x.sh` },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__git__push_changes targeting .claude/memory/x → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__git__push_changes',
      tool_input: { path: `${CWD}\\.claude\\memory\\x.md` },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__db__sync_schema targeting .claude/settings.json → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__db__sync_schema',
      tool_input: { path: `${CWD}\\.claude\\settings.json` },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__git__commit targeting .claude/CLAUDE.md → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__git__commit',
      tool_input: { path: `${CWD}\\.claude\\CLAUDE.md` },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__blob__transfer_file targeting .claude/hooks/x → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__blob__transfer_file',
      tool_input: { destination: `${CWD}\\.claude\\hooks\\x.sh` },
      cwd: CWD,
    },
  },

  // --- v5 audit: getTargetPaths shapes — uri form, object-array files ---
  {
    description: 'mcp__lsp__write with file:// URI → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__lsp__write',
      tool_input: { uri: `file:///${CWD.replace(/\\/g, '/')}/.claude/settings.json`, text: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'mcp__filesystem__write_multiple_files with object-array files → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__filesystem__write_multiple_files',
      tool_input: { files: [{ path: `${CWD}\\.claude\\settings.json`, content: 'evil' }] },
      cwd: CWD,
    },
  },

  // --- v6 audit: file://localhost/PATH form must extract correctly ---
  {
    description: 'mcp__lsp__write with file://localhost/ URI → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__lsp__write',
      tool_input: { uri: `file://localhost/${CWD.replace(/\\/g, '/')}/.claude/settings.json`, text: 'x' },
      cwd: CWD,
    },
  },

  // --- v6 audit: camelCase filePath in object-array files ---
  {
    description: 'mcp__custom__write with object-array {filePath:...} → deny',
    expect: 'deny',
    event: {
      tool_name: 'mcp__custom__write_multiple',
      tool_input: { files: [{ filePath: `${CWD}\\.claude\\settings.json`, content: 'evil' }] },
      cwd: CWD,
    },
  },
];
