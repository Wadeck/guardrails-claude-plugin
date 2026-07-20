'use strict';

// V13 audit bypass vectors.

const CWD = 'C:\\Workspace\\myproject';
function bash(command) { return { tool_name: 'Bash', tool_input: { command }, cwd: CWD }; }

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V13-01: declare/typeset -x PATH= - equivalent to `export PATH=`.
  // V10 added declare/typeset for LD_PRELOAD etc. but PATH was missed.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V13-01a: declare -x PATH=/tmp → deny',
    expect: 'deny',
    event: bash('declare -x PATH=/tmp'),
  },
  {
    description: 'BV-V13-01b: typeset -x PATH=. → deny',
    expect: 'deny',
    event: bash('typeset -x PATH=.'),
  },
  {
    description: 'BV-V13-01c: declare -x PATH=/tmp/evil:$PATH → deny',
    expect: 'deny',
    event: bash('declare -x PATH=/tmp/evil:$PATH'),
  },

  // -------------------------------------------------------------------------
  // BV-V13-02: Dangerous dir in non-first PATH segment.
  // Pattern [^:]* stops at first colon - /safe:/tmp/evil:$PATH bypasses.
  // Fix: use a function pattern that splits on : and checks each segment.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V13-02a: export PATH=/usr/local/bin:/tmp/evil:$PATH → deny',
    expect: 'deny',
    event: bash('export PATH=/usr/local/bin:/tmp/evil:$PATH'),
  },
  {
    description: 'BV-V13-02b: export PATH=/safe/dir:/dev/shm/attacker:$PATH → deny',
    expect: 'deny',
    event: bash('export PATH=/safe/dir:/dev/shm/attacker:$PATH'),
  },
  {
    description: 'BV-V13-02c: env PATH=/usr/local/bin:/tmp/evil:$PATH bash → deny',
    expect: 'deny',
    event: bash('env PATH=/usr/local/bin:/tmp/evil:$PATH bash'),
  },

  // -------------------------------------------------------------------------
  // BV-V13-03: crontab <file> (no flag) - replaces entire crontab.
  // Current pattern requires `-` flag: /crontab\s+-(?!l\b)/
  // -------------------------------------------------------------------------
  {
    description: 'BV-V13-03a: crontab /tmp/evil.cron → deny',
    expect: 'deny',
    event: bash('crontab /tmp/evil.cron'),
  },
  {
    description: 'BV-V13-03b: crontab < /tmp/evil.cron → deny',
    expect: 'deny',
    event: bash('crontab < /tmp/evil.cron'),
  },

  // -------------------------------------------------------------------------
  // BV-V13-04: at -t <POSIX-time> form not in cron-at patterns.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V13-04a: at -t 202601010000 < /tmp/evil.sh → deny',
    expect: 'deny',
    event: bash('at -t 202601010000 < /tmp/evil.sh'),
  },
  {
    description: 'BV-V13-04b: echo "bash /tmp/evil.sh" | at -t 202601010000 → deny',
    expect: 'deny',
    event: bash('echo "bash /tmp/evil.sh" | at -t 202601010000'),
  },

  // -------------------------------------------------------------------------
  // BV-V13-05: iptables/ip6tables with intervening flags before -F/-D.
  // Pattern requires -F immediately after iptables - -v or -t table inserts.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V13-05a: iptables -v -F → deny',
    expect: 'deny',
    event: bash('iptables -v -F'),
  },
  {
    description: 'BV-V13-05b: iptables -t nat -F → deny',
    expect: 'deny',
    event: bash('iptables -t nat -F'),
  },
  {
    description: 'BV-V13-05c: ip6tables -v --flush → deny',
    expect: 'deny',
    event: bash('ip6tables -v --flush'),
  },

  // -------------------------------------------------------------------------
  // BV-V13-06: systemctl with global flags before verb.
  // Pattern: /systemctl\s+(stop|disable|mask|kill)\b/ requires verb right after.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V13-06a: systemctl --now disable sshd → deny',
    expect: 'deny',
    event: bash('systemctl --now disable sshd'),
  },
  {
    description: 'BV-V13-06b: systemctl --user stop myservice → deny',
    expect: 'deny',
    event: bash('systemctl --user stop myservice'),
  },
  {
    description: 'BV-V13-06c: systemctl -q --now mask cron → deny',
    expect: 'deny',
    event: bash('systemctl -q --now mask cron'),
  },

  // -------------------------------------------------------------------------
  // BV-V13-07: echo/printf piped to env with flags before shell name.
  // Pattern: (?:env\s+)? only allows plain `env sh` not `env -i sh`.
  // Fix: change to (?:env\s+(?:\S+\s+)*)? to absorb flags.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V13-07a: echo "rm -rf /" | env -i sh → deny',
    expect: 'deny',
    event: bash('echo "rm -rf /" | env -i sh'),
  },
  {
    description: 'BV-V13-07b: printf "git push -f\\n" | env --ignore-environment bash → deny',
    expect: 'deny',
    event: bash('printf "git push -f\\n" | env --ignore-environment bash'),
  },

  // -------------------------------------------------------------------------
  // BV-V13-08: find -exec rm - rm as -exec argument, not at command-position.
  // All rm patterns require a command-position separator before rm.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V13-08a: find . -name "*.tmp" -exec rm -rf {} \\; → deny',
    expect: 'deny',
    event: bash('find . -name "*.tmp" -exec rm -rf {} \\;'),
  },
  {
    description: 'BV-V13-08b: find /tmp -execdir rm {} + → deny',
    expect: 'deny',
    event: bash('find /tmp -execdir rm {} +'),
  },
  {
    description: 'BV-V13-08c: find . -type f -exec rm {} \\; → deny',
    expect: 'deny',
    event: bash('find . -type f -exec rm {} \\;'),
  },
];
