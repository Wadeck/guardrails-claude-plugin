'use strict';

// V8 audit bypass vectors.

const CWD = 'C:\\Workspace\\myproject';

function bash(command) {
  return { tool_name: 'Bash', tool_input: { command }, cwd: CWD };
}

module.exports = [

  // -------------------------------------------------------------------------
  // BV-V8-01: git category false positives — patterns match inside echo args.
  // `echo "git reset --hard"` triggers git-reset deny even though no reset runs.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V8-01a: echo "git reset --hard HEAD" → allow (git inside echo string)',
    expect: 'allow',
    event: bash('echo "git reset --hard HEAD"'),
  },
  {
    description: 'BV-V8-01b: echo "To push run: git push origin main" → allow',
    expect: 'allow',
    event: bash('echo "To push run: git push origin main"'),
  },
  {
    description: 'BV-V8-01c: echo "reminder: git commit -m msg" → allow',
    expect: 'allow',
    event: bash('echo "reminder: git commit -m msg"'),
  },
  {
    description: 'BV-V8-01d: echo \'git stash\' → allow (single-quoted)',
    expect: 'allow',
    event: bash("echo 'git stash'"),
  },
  {
    description: 'BV-V8-01e: actual git reset still triggers → deny',
    expect: 'deny',
    event: bash('git reset --hard HEAD'),
  },
  {
    description: 'BV-V8-01f: actual git push still triggers → deny',
    expect: 'deny',
    event: bash('git push origin main'),
  },

  // -------------------------------------------------------------------------
  // BV-V8-02: protected_files with null entry crashes matchProtectedFiles.
  // Rule after null is never evaluated → fail-open on the entire protected_files check.
  // -------------------------------------------------------------------------
  // Note: guardrailsConfig tests use the tmpDir as cwd (set by run-tests harness).
  // File paths must therefore be relative (resolved against tmpDir by the script).
  {
    description: 'BV-V8-02a: protected_files [null, deny rule] — null must not crash, deny rule applies',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [null, { glob: '.env', decision: 'deny' }],
    },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.env', content: 'x' },
    },
  },
  {
    description: 'BV-V8-02b: protected_files with non-object entries skipped gracefully',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [42, 'bad', null, { glob: '*.key', decision: 'deny' }],
    },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'server.key', content: 'x' },
    },
  },

  // -------------------------------------------------------------------------
  // BV-V8-03: globToRegExp does not handle brace expansion {a,b,...}.
  // A rule `{settings,guardrails}.json` never matches.
  // -------------------------------------------------------------------------
  {
    description: 'BV-V8-03a: protected glob {settings,guardrails}.json matches settings.json',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [{ glob: '{settings,guardrails}.json', decision: 'deny' }],
    },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'settings.json', content: 'x' },
    },
  },
  {
    description: 'BV-V8-03b: protected glob {settings,guardrails}.json matches guardrails.json',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [{ glob: '{settings,guardrails}.json', decision: 'deny' }],
    },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'guardrails.json', content: 'x' },
    },
  },
  {
    description: 'BV-V8-03c: protected glob {a,b,c}.txt matches b.txt',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [{ glob: '{a,b,c}.txt', decision: 'deny' }],
    },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'b.txt', content: 'x' },
    },
  },
];
