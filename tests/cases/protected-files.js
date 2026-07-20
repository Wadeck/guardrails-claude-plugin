'use strict';

// protected_files - path-based write protection using glob patterns.
// Config: { "protected_files": [{ "glob": "**/*.pem", "decision": "deny" }, ...] }
// Patterns are relative to the project root.
// Most restrictive match wins: deny > ask > allow.

const CWD = 'C:\\Workspace\\myproject';

module.exports = [
  // --- Basic deny / ask ---

  {
    description: 'Edit a .pem file in subdir matching **/*.pem → deny',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: '**/*.pem', decision: 'deny' }] },
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: 'certs/server.pem', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  {
    description: 'Write a file matching src/config/** → ask',
    expect: 'ask',
    guardrailsConfig: { protected_files: [{ glob: 'src/config/**', decision: 'ask' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'src/config/database.js', content: 'x' },
      cwd: CWD,
    },
  },

  // --- ** matches any depth ---

  {
    description: '**/*.pem matches deeply nested file',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: '**/*.pem', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'a/b/c/server.pem', content: 'x' },
      cwd: CWD,
    },
  },

  {
    description: '**/*.pem also matches root-level .pem (** makes prefix optional)',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: '**/*.pem', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'server.pem', content: 'x' },
      cwd: CWD,
    },
  },

  // --- Single * does not cross / ---

  {
    description: '*.pem does not match file in subdirectory',
    expect: 'allow',
    guardrailsConfig: { protected_files: [{ glob: '*.pem', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'certs/server.pem', content: 'x' },
      cwd: CWD,
    },
  },

  {
    description: '*.pem matches root-level .pem file',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: '*.pem', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'server.pem', content: 'x' },
      cwd: CWD,
    },
  },

  // --- Most restrictive wins when multiple patterns match ---

  {
    description: 'Multiple patterns both match → deny wins over ask',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [
        { glob: 'src/**',    decision: 'ask'  },
        { glob: '**/*.pem',  decision: 'deny' },
      ],
    },
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: 'src/certs/server.pem', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  // --- Bash: write path extracted from command ---

  {
    description: 'Bash redirect to a protected file path → deny',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: '**/*.pem', decision: 'deny' }] },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'echo "data" > certs/server.pem' },
      cwd: CWD,
    },
  },

  // --- Non-matching paths ---

  {
    description: 'File that matches no protected pattern → allow',
    expect: 'allow',
    guardrailsConfig: { protected_files: [{ glob: '**/*.pem', decision: 'deny' }] },
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: 'src/index.js', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  // --- .env* pattern at root ---

  {
    description: '.env* matches .env.local at root → deny',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: '.env*', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.env.local', content: 'SECRET=x' },
      cwd: CWD,
    },
  },

  {
    description: '.env* does not match .env file in subdirectory',
    expect: 'allow',
    guardrailsConfig: { protected_files: [{ glob: '.env*', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'sub/.env.local', content: 'x' },
      cwd: CWD,
    },
  },

  // --- No protected_files → no change ---

  {
    description: 'No protected_files in config → allow',
    expect: 'allow',
    guardrailsConfig: {},
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: 'src/config/db.js', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  // --- File outside project → no match ---

  {
    description: 'File outside project dir does not match any protected pattern',
    expect: 'allow',
    guardrailsConfig: { protected_files: [{ glob: '**/*.pem', decision: 'deny' }] },
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: 'C:\\OtherProject\\server.pem', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  // --- NotebookEdit ---

  {
    description: 'NotebookEdit on a protected notebook path → ask',
    expect: 'ask',
    guardrailsConfig: { protected_files: [{ glob: 'notebooks/**', decision: 'ask' }] },
    event: {
      tool_name: 'NotebookEdit',
      tool_input: { notebook_path: 'notebooks/analysis.ipynb', new_source: 'x', cell_number: 0, edit_mode: 'replace' },
      cwd: CWD,
    },
  },

  // --- Invalid / malformed rules are silently skipped ---

  {
    description: 'Rule with missing glob field → skipped, allow',
    expect: 'allow',
    guardrailsConfig: { protected_files: [{ decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'server.pem', content: 'x' },
      cwd: CWD,
    },
  },

  {
    description: 'Rule with unknown decision value → skipped, allow',
    expect: 'allow',
    guardrailsConfig: { protected_files: [{ glob: '**/*.pem', decision: 'block' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'server.pem', content: 'x' },
      cwd: CWD,
    },
  },

  // --- Accumulation with category matches ---
  // protected_files and category matches are consolidated: most restrictive wins,
  // multiple ask-level matches appear together in the multi-ask dialog.

  {
    description: 'Bash: protected_files ask + category ask → ask (both visible in reason)',
    expect: 'ask',
    expectReasonIncludes: 'protected-files',
    guardrailsConfig: {
      protected_files: [{ glob: 'important/**', decision: 'ask' }],
      categories: { rm: 'ask' },
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm important/data.txt' },
      cwd: CWD,
    },
  },

  {
    description: 'Bash: protected_files ask + category deny → deny wins',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [{ glob: 'important/**', decision: 'ask' }],
      categories: { rm: 'deny' },
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm important/data.txt' },
      cwd: CWD,
    },
  },

  {
    description: 'Bash: protected_files deny + category ask → deny wins',
    expect: 'deny',
    guardrailsConfig: {
      protected_files: [{ glob: 'important/**', decision: 'deny' }],
      categories: { rm: 'ask' },
    },
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm important/data.txt' },
      cwd: CWD,
    },
  },

  {
    description: 'Edit: protected_files deny is logged with trigger name protected-files',
    expect: 'deny',
    expectReasonIncludes: 'protected-files',
    guardrailsConfig: { protected_files: [{ glob: '**/*.key', decision: 'deny' }] },
    event: {
      tool_name: 'Edit',
      tool_input: { file_path: 'secrets/id_rsa.key', old_string: 'a', new_string: 'b' },
      cwd: CWD,
    },
  },

  // --- v4 audit MEDIUM: protected_files with "ask" on .claude/ paths must be
  // upgraded to "deny" because Claude Code silently auto-approves ask under
  // .claude/ (no PermissionRequest event). User-defined ask offers no real
  // protection in that scope.
  {
    description: 'protected_files ask on .claude/custom.json → upgraded to deny',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: '.claude/custom.json', decision: 'ask' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: '.claude/custom.json', content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'protected_files ask on src/config/** (outside .claude/) → stays ask',
    expect: 'ask',
    guardrailsConfig: { protected_files: [{ glob: 'src/config/**', decision: 'ask' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'src/config/app.yml', content: 'x' },
      cwd: CWD,
    },
  },

  // --- Case-insensitive glob: uppercase pattern matches lowercase path ---
  {
    description: 'Glob "**/*.PEM" (uppercase) matches "certs/server.pem" (lowercase)',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: '**/*.PEM', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'certs/server.pem', content: 'x' },
      cwd: CWD,
    },
  },
  {
    description: 'Glob "Secrets/**" (mixed case) matches "secrets/x"',
    expect: 'deny',
    guardrailsConfig: { protected_files: [{ glob: 'Secrets/**', decision: 'deny' }] },
    event: {
      tool_name: 'Write',
      tool_input: { file_path: 'secrets/x.json', content: 'x' },
      cwd: CWD,
    },
  },
];
