'use strict';

// V15 audit bypass vectors.

const CWD = 'C:\\Workspace\\myproject';
function bash(command) { return { tool_name: 'Bash', tool_input: { command }, cwd: CWD }; }

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V15-01: rsync write bypass — not in extractBashWritePaths or any category.
  // rsync is a standard file-copy tool; rsync src dst overwrites dst with no warning.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V15-01a: rsync evil.json .claude/settings.json → deny',
    expect: 'deny',
    event: bash('rsync evil.json .claude/settings.json'),
  },
  {
    description: 'BV-V15-01b: rsync -av /tmp/evil.json .claude/guardrails.json → deny',
    expect: 'deny',
    event: bash('rsync -av /tmp/evil.json .claude/guardrails.json'),
  },
  {
    description: 'BV-V15-01c: rsync -r /tmp/evil/ .claude/hooks/ → deny',
    expect: 'deny',
    event: bash('rsync -r /tmp/evil/ .claude/hooks/'),
  },

  // -------------------------------------------------------------------------
  // BV-V15-02: find -delete false positive on --delete-* flags in tool names.
  // Pattern `\bfind\b[^|&;]*-delete\b` matches "find" in hyphenated tool names
  // and "-delete" inside "--delete-orphans" or "--delete-existing".
  // Fix: require command-position anchor for `find` (same separator set as rm).
  // -------------------------------------------------------------------------
  {
    description: 'BV-V15-02a: npx find-and-replace-cli --delete-old-files → allow (not deny)',
    expect: 'allow',
    event: bash('npx find-and-replace-cli --delete-old-files'),
  },
  {
    description: 'BV-V15-02b: some-tool find-artifacts --delete-orphans → allow',
    expect: 'allow',
    event: bash('some-tool find-artifacts --delete-orphans'),
  },
  // Verify genuine find -delete still fires:
  {
    description: 'BV-V15-02c: find . -name "*.bak" -delete → deny (genuine case)',
    expect: 'deny',
    event: bash('find . -name "*.bak" -delete'),
  },

  // -------------------------------------------------------------------------
  // BV-V15-03: printf multi-arg false positive — second quoted arg not stripped.
  // stripEchoArgs only strips the first quoted argument immediately after printf.
  // After stripping '%s\n', the result is `printf  'git stash'` → git-stash fires.
  // Fix: strip ALL consecutive literal quoted args following echo/printf.
  // -------------------------------------------------------------------------
  {
    description: "BV-V15-03a: printf '%s\\n' 'git stash' → allow (just printing)",
    expect: 'allow',
    event: bash("printf '%s\\n' 'git stash'"),
  },
  {
    description: "BV-V15-03b: printf '%s\\n' 'git push origin main' → allow",
    expect: 'allow',
    event: bash("printf '%s\\n' 'git push origin main'"),
  },
  {
    description: 'BV-V15-03c: printf "%-20s" "git reset --hard" → allow',
    expect: 'allow',
    event: bash('printf "%-20s" "git reset --hard"'),
  },

  // -------------------------------------------------------------------------
  // BV-V15-04: PATH bare $HOME (no trailing slash) not caught.
  // WRITABLE requires `$HOME/` or `${HOME}/` but `${HOME}:$PATH` (bare home dir) passes.
  // Fix: accept `$HOME` followed by /, :, or end of segment.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V15-04a: export PATH=${HOME}:$PATH → deny',
    expect: 'deny',
    event: bash('export PATH=${HOME}:$PATH'),
  },
  {
    description: 'BV-V15-04b: export PATH=$HOME:$PATH → deny',
    expect: 'deny',
    event: bash('export PATH=$HOME:$PATH'),
  },
];
