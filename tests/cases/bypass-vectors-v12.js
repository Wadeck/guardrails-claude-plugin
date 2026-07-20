'use strict';

// V12 audit bypass vectors.

const CWD = 'C:\\Workspace\\myproject';
function bash(command) { return { tool_name: 'Bash', tool_input: { command }, cwd: CWD }; }

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V12-01: sponge inside process substitution — trailing ) not stripped.
  // The bare sponge extractor captures "settings.json)" because sponge is
  // inside >(sponge ...) and the ) is not in the exclusion set.
  // V10 fixed tee the same way — apply the same strip to sponge.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V12-01a: echo "{}" > >(sponge .claude/settings.json) → deny',
    expect: 'deny',
    event: bash('echo "{}" > >(sponge .claude/settings.json)'),
  },
  {
    description: 'BV-V12-01b: cat evil.json > >(sponge .claude/guardrails.json) → deny',
    expect: 'deny',
    event: bash('cat evil.json > >(sponge .claude/guardrails.json)'),
  },

  // -------------------------------------------------------------------------
  // BV-V12-02: env PATH=... — env command form not covered for PATH injection.
  // V11 added env LD_PRELOAD= patterns but not PATH=.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V12-02a: env PATH=/tmp/evil:$PATH git commit → deny',
    expect: 'deny',
    event: bash('env PATH=/tmp/evil:$PATH git commit'),
  },
  {
    description: 'BV-V12-02b: env PATH=. git push → deny',
    expect: 'deny',
    event: bash('env PATH=. git push'),
  },
  {
    description: 'BV-V12-02c: env PATH=/dev/shm bash → deny',
    expect: 'deny',
    event: bash('env PATH=/dev/shm bash'),
  },

  // -------------------------------------------------------------------------
  // BV-V12-03: Non-standard shell paths bypass pipe-to-shell detection.
  // Pattern only allows /bin/, /usr/bin/, /usr/local/bin/. Homebrew on Apple
  // Silicon installs to /opt/homebrew/bin/; snap to /snap/bin/.
  // Fix: replace strict prefix alternation with any-prefix `(?:[^\s|&;]*/)?`.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V12-03a: echo "rm -rf .claude/" | /opt/homebrew/bin/bash → deny',
    expect: 'deny',
    event: bash('echo "rm -rf .claude/" | /opt/homebrew/bin/bash'),
  },
  {
    description: 'BV-V12-03b: echo "git push -f" | /snap/bin/zsh → deny',
    expect: 'deny',
    event: bash('echo "git push --force" | /snap/bin/zsh'),
  },
  {
    description: 'BV-V12-03c: echo "evil" | /home/user/.local/bin/bash → deny',
    expect: 'deny',
    event: bash('echo "evil" | /home/user/.local/bin/bash'),
  },

  // -------------------------------------------------------------------------
  // BV-V12-04: Multi-source cp — third+ token is destination, extractor captures second.
  // cp src1 src2 dst: extractor regex takes \S+\s+(\S+) after flags, capturing src2.
  // dst (.claude/settings.json) is never extracted → settings-write misses.
  // Fix: also push the last non-flag token from the argument segment.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V12-04a: cp /dev/null extra.txt .claude/settings.json → deny',
    expect: 'deny',
    event: bash('cp /dev/null extra.txt .claude/settings.json'),
  },
  {
    description: 'BV-V12-04b: mv a.txt b.txt .claude/guardrails.json → deny',
    expect: 'deny',
    event: bash('mv a.txt b.txt .claude/guardrails.json'),
  },
  {
    description: 'BV-V12-04c: cp -f src1 src2 .claude/hooks/evil.sh → deny',
    expect: 'deny',
    event: bash('cp -f src1 src2 .claude/hooks/evil.sh'),
  },
];
