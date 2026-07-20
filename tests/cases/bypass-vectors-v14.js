'use strict';

// V14 audit bypass vectors.

const CWD = 'C:\\Workspace\\myproject';
function bash(command) { return { tool_name: 'Bash', tool_input: { command }, cwd: CWD }; }

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V14-01: PATH outer-quote bypass - quoted assignment hides the path.
  // The PATH function captures `"/tmp/evil:$PATH"` (with outer quote), then
  // splits on `:` → first segment is `"/tmp/evil` which fails WRITABLE regex.
  // Fix: strip leading/trailing quotes from the captured value before splitting.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V14-01a: export PATH="/tmp/evil:$PATH" → deny',
    expect: 'deny',
    event: bash('export PATH="/tmp/evil:$PATH"'),
  },
  {
    description: "BV-V14-01b: export PATH='/tmp/evil:$PATH' → deny",
    expect: 'deny',
    event: bash("export PATH='/tmp/evil:$PATH'"),
  },
  {
    description: 'BV-V14-01c: declare -x PATH="/tmp/evil" → deny',
    expect: 'deny',
    event: bash('declare -x PATH="/tmp/evil"'),
  },

  // -------------------------------------------------------------------------
  // BV-V14-02: PATH ${HOME} curly-brace bypass.
  // WRITABLE regex matches `$HOME/` (no braces) but not `${HOME}/`.
  // Fix: add `\$\{HOME\}\/` to WRITABLE, or normalise ${VAR} → $VAR first.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V14-02a: export PATH=${HOME}/evil:$PATH → deny',
    expect: 'deny',
    event: bash('export PATH=${HOME}/evil:$PATH'),
  },
  {
    description: 'BV-V14-02b: export PATH=${HOME}/bin → deny',
    expect: 'deny',
    event: bash('export PATH=${HOME}/bin'),
  },

  // -------------------------------------------------------------------------
  // BV-V14-03: find -exec /bin/rm - absolute path not matched.
  // Pattern `\\?rm\b` requires rm at start of the -exec argument.
  // /bin/rm places /bin/ before rm; regex engine can't match.
  // Fix: add `(?:[^\s|&;]*/)?` optional prefix before rm in the pattern.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V14-03a: find . -exec /bin/rm -rf {} \\; → deny',
    expect: 'deny',
    event: bash('find . -exec /bin/rm -rf {} \\;'),
  },
  {
    description: 'BV-V14-03b: find /tmp -execdir /usr/bin/rm {} + → deny',
    expect: 'deny',
    event: bash('find /tmp -execdir /usr/bin/rm {} +'),
  },

  // -------------------------------------------------------------------------
  // BV-V14-04: find -delete builtin - no rm keyword involved.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V14-04a: find .claude -name "*.json" -delete → deny',
    expect: 'deny',
    event: bash('find .claude -name "*.json" -delete'),
  },
  {
    description: 'BV-V14-04b: find . -name "*.bak" -delete → deny',
    expect: 'deny',
    event: bash('find . -name "*.bak" -delete'),
  },

  // -------------------------------------------------------------------------
  // BV-V14-05: Function pattern ignores stripEchoArgs - false positive.
  // PATH function receives original command, not stripped, so an echo message
  // mentioning PATH=/tmp/evil incorrectly triggers env-hijack deny.
  // Fix: pass testCmd to function patterns (same stripping as RegExp patterns).
  // -------------------------------------------------------------------------
  {
    description: 'BV-V14-05a: echo "export PATH=/tmp/evil:$PATH" → allow (not deny)',
    expect: 'allow',
    event: bash('echo "export PATH=/tmp/evil:$PATH"'),
  },
  {
    description: 'BV-V14-05b: echo "PATH hijack example: export PATH=/tmp:$PATH" → allow',
    expect: 'allow',
    event: bash('echo "PATH hijack example: export PATH=/tmp:$PATH"'),
  },

  // -------------------------------------------------------------------------
  // BV-V14-06: ${HOME} not expanded in extractBashWritePaths.
  // expandTilde handles ~ but not ${HOME}. The path is treated as relative,
  // joined to projectDir, and never matches .claude/.
  // Fix: expand ${HOME} (and ${USERPROFILE}) in expandTilde.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V14-06a: echo "{}" > "${HOME}/.claude/settings.json" → deny',
    expect: 'deny',
    event: bash('echo "{}" > "${HOME}/.claude/settings.json"'),
  },
  {
    description: 'BV-V14-06b: cp evil.json "${HOME}/.claude/guardrails.json" → deny',
    expect: 'deny',
    event: bash('cp evil.json "${HOME}/.claude/guardrails.json"'),
  },

  // -------------------------------------------------------------------------
  // BV-V14-07: git push colon-refspec deletes remote branch silently.
  // With `"git-push": "allow"` in config, `git push origin :main` bypasses
  // git-branch-delete (which requires --delete or -d/-D).
  // Fix: add colon-refspec form to git-branch-delete patterns.
  // This test uses default config (no allow override) - git-push fires, which
  // is already deny. The real config-interaction gap is tested implicitly;
  // adding the pattern to git-branch-delete is correctness, not just safety.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V14-07a: git push origin :main → deny (branch-delete via colon-refspec)',
    expect: 'deny',
    event: bash('git push origin :main'),
  },
  {
    description: 'BV-V14-07b: git push origin :refs/heads/feature → deny',
    expect: 'deny',
    event: bash('git push origin :refs/heads/feature'),
  },
];
