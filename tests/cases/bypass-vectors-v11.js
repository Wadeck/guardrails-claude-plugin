'use strict';

// V11 audit bypass vectors.

const CWD = 'C:\\Workspace\\myproject';
function bash(command) { return { tool_name: 'Bash', tool_input: { command }, cwd: CWD }; }

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V11-01: Three-pipe eval — echo through TWO intermediates then shell.
  // V10 one-intermediate pattern stops at (echo | X | shell). Two intermediates
  // (echo | X | Y | shell) slip past because the second [^|&;]* matches "Y"
  // and the final \|\s*shell never gets a chance to see the last pipe.
  // Fix: generalise to (?:\|[^|&;]*)* before the final \|\s*shell.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V11-01a: echo "rm" | tee a | tee b | sh → deny',
    expect: 'deny',
    event: bash('echo "rm -rf .claude/" | tee /tmp/a.sh | tee /tmp/b.sh | sh'),
  },
  {
    description: 'BV-V11-01b: printf "git push -f" | cat | tee s | bash → deny',
    expect: 'deny',
    event: bash('printf "git push -f origin main\n" | cat | tee /tmp/s.sh | bash'),
  },
  {
    description: 'BV-V11-01c: echo "LD_PRELOAD=evil" | tee a | tee b | zsh → deny',
    expect: 'deny',
    event: bash('echo "export LD_PRELOAD=/tmp/evil.so" | tee /tmp/a | tee /tmp/b | zsh'),
  },

  // -------------------------------------------------------------------------
  // BV-V11-02: echo/printf piped to xargs acting as shell executor.
  // `xargs -I{} sh -c {}` passes the full stdin line as -c arg to shell.
  // xargs is not in the shell-name list, so neither V9 nor V10 patterns fire.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V11-02a: printf "rm -rf x" | xargs -d\\n bash -c → deny',
    expect: 'deny',
    event: bash("printf 'rm -rf /tmp/evil\\n' | xargs -d'\\n' bash -c"),
  },
  {
    description: "BV-V11-02b: echo 'git push -f' | xargs -I{} sh -c {} → deny",
    expect: 'deny',
    event: bash("echo 'git push -f origin main' | xargs -I{} sh -c {}"),
  },

  // -------------------------------------------------------------------------
  // BV-V11-03: sponge (moreutils) — not in extractBashWritePaths.
  // sponge reads all stdin then atomically writes to the named file.
  // No redirect, no tee, no category match — all checks see empty targetPaths.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V11-03a: printf "{}" | sponge .claude/settings.json → deny',
    expect: 'deny',
    event: bash('printf "%s" "{}" | sponge .claude/settings.json'),
  },
  {
    description: 'BV-V11-03b: cat /dev/null | sponge .claude/guardrails.json → deny',
    expect: 'deny',
    event: bash('cat /dev/null | sponge .claude/guardrails.json'),
  },
  {
    description: 'BV-V11-03c: echo evil | sponge .claude/hooks/pre-tool-use.sh → deny',
    expect: 'deny',
    event: bash('echo evil | sponge .claude/hooks/pre-tool-use.sh'),
  },

  // -------------------------------------------------------------------------
  // BV-V11-04a: export PATH=$HOME/... and /home/user/... — not in PATH pattern.
  // V10 pattern only blocks /tmp, /dev/shm, /var/tmp, and literal ~/. $HOME and
  // /home/user/ are user-writable and not covered.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V11-04a-1: export PATH=$HOME/.local/bin:$PATH → deny',
    expect: 'deny',
    event: bash('export PATH=$HOME/.local/bin:$PATH'),
  },
  {
    description: 'BV-V11-04a-2: export PATH=/home/attacker/bin:$PATH → deny',
    expect: 'deny',
    event: bash('export PATH=/home/attacker/bin:$PATH'),
  },

  // -------------------------------------------------------------------------
  // BV-V11-04b: export PATH=/tmp (pure replacement, no trailing colon).
  // V10 pattern: [^:]*(\/tmp)[^:]*: — requires a colon after the dir.
  // Pure replacement (no $PATH appended) bypasses because there is no colon.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V11-04b-1: export PATH=/tmp → deny',
    expect: 'deny',
    event: bash('export PATH=/tmp'),
  },
  {
    description: 'BV-V11-04b-2: export PATH=/dev/shm → deny',
    expect: 'deny',
    event: bash('export PATH=/dev/shm'),
  },

  // -------------------------------------------------------------------------
  // BV-V11-05: env LD_PRELOAD=... cmd — env(1) form not in env-hijack.
  // Distinct from BV-NEW-03 (inline without keyword). env command prefix is a
  // POSIX standard form not requiring any shell keyword.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V11-05a: env LD_PRELOAD=/tmp/evil.so node app.js → deny',
    expect: 'deny',
    event: bash('env LD_PRELOAD=/tmp/evil.so node app.js'),
  },
  {
    description: 'BV-V11-05b: env -i LD_PRELOAD=/tmp/evil.so git status → deny',
    expect: 'deny',
    event: bash('env -i LD_PRELOAD=/tmp/evil.so git status'),
  },
  {
    description: 'BV-V11-05c: env LD_LIBRARY_PATH=/dev/shm bash → deny',
    expect: 'deny',
    event: bash('env LD_LIBRARY_PATH=/dev/shm bash'),
  },
];
