'use strict';

// Tests for secrets-file-access detection: any Bash command that mentions a protected
// secrets file by name is blocked regardless of operation or path form.
// Detection is basename-based - the full path is irrelevant.

const LINKED_ENV_CONTENT = 'SLACK_USER_TOKEN=xoxp-fake-token-for-testing\n';

function makeConfig(overrides) {
  return {
    secrets: {
      file: '.claude/guardrails.secrets',
      redirect_message: 'Use the CLI instead.',
    },
    ...overrides,
  };
}

const BASE_FILES = {
  '.claude/guardrails.secrets': '@slack-cli/.env.local\n',
  'slack-cli/.env.local': LINKED_ENV_CONTENT,
  '.gitignore': '.claude/guardrails.secrets\n',
};

module.exports = [

  // -------------------------------------------------------------------------
  // source / dot - blocked
  // -------------------------------------------------------------------------
  {
    description: 'source .env.local - shell source',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'source slack-cli/.env.local && node index.js' } },
  },
  {
    description: '. .env.local - POSIX dot-source',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: '. slack-cli/.env.local' } },
  },
  {
    description: 'source guardrails.secrets - direct source of registry file',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'source .claude/guardrails.secrets' } },
  },

  // -------------------------------------------------------------------------
  // Read operations - blocked
  // -------------------------------------------------------------------------
  {
    description: 'cat .env.local',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'cat slack-cli/.env.local' } },
  },
  {
    description: 'head .env.local',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'head slack-cli/.env.local' } },
  },
  {
    description: 'tail .env.local',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'tail -n 5 slack-cli/.env.local' } },
  },
  {
    description: 'grep TOKEN .env.local',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'grep TOKEN slack-cli/.env.local' } },
  },
  {
    description: 'less .env.local',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'less slack-cli/.env.local' } },
  },

  // -------------------------------------------------------------------------
  // Copy / move operations - blocked
  // -------------------------------------------------------------------------
  {
    description: 'cp .env.local /tmp/copy',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'cp slack-cli/.env.local /tmp/copy' } },
  },
  {
    description: 'mv .env.local /tmp/moved',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'mv slack-cli/.env.local /tmp/moved' } },
  },

  // -------------------------------------------------------------------------
  // Basename match - blocked regardless of subproject or path form
  // -------------------------------------------------------------------------
  {
    description: 'cat github-cli/.env.local - different subproject, same filename',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'cat github-cli/.env.local' } },
  },
  {
    description: 'cd slack-cli && source .env.local - basename caught despite cd',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'cd slack-cli && source .env.local' } },
  },
  {
    description: 'echo hi && cat slack-cli/.env.local - blocked after && separator',
    expect: 'deny',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'echo hi && cat slack-cli/.env.local' } },
  },

  // -------------------------------------------------------------------------
  // Unrelated filenames - allowed
  // -------------------------------------------------------------------------
  {
    description: 'cat slack-cli/.env - different filename (allow)',
    expect: 'allow',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'cat slack-cli/.env' } },
  },
  {
    description: 'source .env - different filename (allow)',
    expect: 'allow',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'source .env' } },
  },

  // -------------------------------------------------------------------------
  // Suffix guard: basename ".env.local" must not fire on ".env.local.bak" or ".env.local.example"
  // -------------------------------------------------------------------------
  {
    description: 'cat .env.local.bak - suffix extends basename, no match (allow)',
    expect: 'allow',
    guardrailsConfig: makeConfig(),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'cat .env.local.bak' } },
  },

  // -------------------------------------------------------------------------
  // secrets-file-access: allow override
  // -------------------------------------------------------------------------
  {
    description: 'cat .env.local with secrets-file-access: allow in config',
    expect: 'allow',
    guardrailsConfig: makeConfig({ categories: { 'secrets-file-access': 'allow' } }),
    extraFiles: BASE_FILES,
    event: { tool_name: 'Bash', tool_input: { command: 'cat slack-cli/.env.local' } },
  },
];
