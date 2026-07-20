'use strict';

// V17 audit bypass vectors.

const CWD = 'C:\\Workspace\\myproject';
function bash(command) { return { tool_name: 'Bash', tool_input: { command }, cwd: CWD }; }
function mcp(toolName, toolInput) { return { tool_name: toolName, tool_input: toolInput, cwd: CWD }; }

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V17-01: install --target-directory DIR (space form, not =).
  // The extractor only handles `--target-directory=VALUE`. With a space, the
  // flag hits the bare `continue`, and the first positional is the source.
  // Fix: treat `--target-directory` (exact tok) same as `-t` - consume next.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V17-01a: install --target-directory .claude/hooks/ payload.sh → deny',
    expect: 'deny',
    event: bash('install --target-directory .claude/hooks/ payload.sh'),
  },
  {
    description: 'BV-V17-01b: install -D --target-directory .claude/hooks/ payload.sh → deny',
    expect: 'deny',
    event: bash('install -D --target-directory .claude/hooks/ payload.sh'),
  },

  // -------------------------------------------------------------------------
  // BV-V17-02: export multi-assignment - dangerous var after innocuous one.
  // `/export\s+LD_PRELOAD=/i` requires LD_PRELOAD immediately after `export\s+`.
  // `export DUMMY=1 LD_PRELOAD=/tmp/evil.so` inserts DUMMY=1 first → no match.
  // Fix: use `(?:export|declare|typeset)\b[^|&;\n\r]*\bLD_PRELOAD=` etc.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V17-02a: export DUMMY=1 LD_PRELOAD=/tmp/evil.so → deny',
    expect: 'deny',
    event: bash('export DUMMY=1 LD_PRELOAD=/tmp/evil.so'),
  },
  {
    description: 'BV-V17-02b: export A=1 B=2 DYLD_INSERT_LIBRARIES=/tmp/evil.dylib → deny',
    expect: 'deny',
    event: bash('export A=1 B=2 DYLD_INSERT_LIBRARIES=/tmp/evil.dylib'),
  },
  {
    description: 'BV-V17-02c: export DUMMY=1 LD_LIBRARY_PATH=/dev/shm/evil → deny',
    expect: 'deny',
    event: bash('export DUMMY=1 LD_LIBRARY_PATH=/dev/shm/evil'),
  },
  {
    description: 'BV-V17-02d: declare -x DUMMY=1 LD_PRELOAD=/tmp/evil.so → deny',
    expect: 'deny',
    event: bash('declare -x DUMMY=1 LD_PRELOAD=/tmp/evil.so'),
  },

  // -------------------------------------------------------------------------
  // BV-V17-03: awk '{inline}' -i inplace file - script BEFORE -i inplace.
  // The extractor skips tokens seen before droppedInplace=true. After -i inplace,
  // the first non-flag gets droppedScript=true and is skipped as the inline
  // script. But the actual script was already seen - the file is the remaining
  // token which is incorrectly treated as script.
  // Fix: two-pass or pre-inplace non-flag collection.
  // -------------------------------------------------------------------------
  {
    description: "BV-V17-03a: awk '{print}' -i inplace .claude/settings.json → deny",
    expect: 'deny',
    event: bash("awk '{print}' -i inplace .claude/settings.json"),
  },
  {
    description: "BV-V17-03b: gawk '{gsub(/a/,\"b\")}' -i inplace .claude/guardrails.json → deny",
    expect: 'deny',
    event: bash('gawk \'{gsub(/a/,"b")}\' -i inplace .claude/guardrails.json'),
  },

  // -------------------------------------------------------------------------
  // BV-V17-04: echo "source /tmp/..." false positive (INFO).
  // eval category uses testCmd=command for ALL patterns (because patterns[0]
  // is a function). Source/dot patterns fire on the original, including text
  // inside echo-quoted strings.
  // Fix: convert source/dot patterns to lambdas using the `stripped` arg.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V17-04a: echo "run: source /tmp/vendor/setup.sh" → allow (false positive)',
    expect: 'allow',
    event: bash('echo "To configure the app, run: source /tmp/vendor/setup.sh"'),
  },
  {
    description: 'BV-V17-04b: echo "example: . /tmp/env.sh" → allow (false positive)',
    expect: 'allow',
    event: bash('echo "example: . /tmp/env.sh"'),
  },
  // Verify genuine source /tmp/... still fires:
  {
    description: 'BV-V17-04c: source /tmp/evil.sh → deny (genuine)',
    expect: 'deny',
    event: bash('source /tmp/evil.sh'),
  },

  // -------------------------------------------------------------------------
  // BV-V17-05: MCP `file` key not screened by getTargetPaths.
  // The single-path key list lacks `file`. A tool with `{ file: path }` passes
  // isWriteCapableTool but path is never extracted, so all checks are skipped.
  // Fix: add 'file' to the single-path key list.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V17-05a: mcp write with file key targeting .claude/settings.json → deny',
    expect: 'deny',
    event: mcp('mcp__fs__write_file', { file: '.claude/settings.json', content: '{}' }),
  },
  {
    description: 'BV-V17-05b: mcp write with file key targeting .claude/guardrails.json → deny',
    expect: 'deny',
    event: mcp('mcp__fs__create_file', { file: '.claude/guardrails.json', content: '{}' }),
  },
];
