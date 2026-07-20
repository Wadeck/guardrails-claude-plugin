'use strict';

// extractBashWritePaths must surface destination paths for tools that write
// files indirectly (in-place edits, archive extraction, key generation, etc.).
// Without this, an attacker can target protected paths (.claude/...) via tools
// the path-extraction layer doesn't recognize, bypassing every path-based check.
//
// Each case targets .claude/settings.json (settings-write deny) so a successful
// extraction → deny, a missed extraction → allow.

const CWD = 'C:\\Workspace\\myproject';
const bash = (command) => ({ tool_name: 'Bash', tool_input: { command }, cwd: CWD });

module.exports = [
  // --- sed -i (in-place) ---
  {
    description: 'sed -i targeting .claude/settings.json → deny via settings-write',
    expect: 'deny',
    event: bash('sed -i "s/old/new/" .claude/settings.json'),
  },
  {
    description: 'sed -i.bak targeting .claude/settings.json → deny',
    expect: 'deny',
    event: bash('sed -i.bak "s/x/y/" .claude/settings.json'),
  },
  {
    description: 'sed --in-place targeting .claude/settings.json → deny',
    expect: 'deny',
    event: bash('sed --in-place "s/x/y/" .claude/settings.json'),
  },
  // sed -i -e variants - script supplied via -e, file is the only remaining token
  {
    description: 'sed -i -e SCRIPT FILE → deny (audit v4 finding HIGH)',
    expect: 'deny',
    event: bash("sed -i -e 's/old/new/' .claude/settings.json"),
  },
  {
    description: 'sed -ni -f /tmp/script.sed FILE → deny',
    expect: 'deny',
    event: bash('sed -ni -f /tmp/script.sed .claude/memory/x.md'),
  },
  {
    description: 'sed -i -e A -e B FILE → deny (multiple -e)',
    expect: 'deny',
    event: bash("sed -i -e 's/a/b/' -e 's/c/d/' .claude/guardrails.json"),
  },

  // --- perl -pi -e ---
  {
    description: 'perl -pi -e targeting .claude/settings.json → deny',
    expect: 'deny',
    event: bash('perl -pi -e "s/x/y/" .claude/settings.json'),
  },
  {
    description: 'perl -i -pe targeting .claude/settings.json → deny',
    expect: 'deny',
    event: bash('perl -i -pe "s/x/y/" .claude/settings.json'),
  },

  // --- openssl -out / gpg --output ---
  {
    description: 'openssl genrsa -out .claude/hooks/x → deny',
    expect: 'deny',
    event: bash('openssl genrsa -out .claude/hooks/x.pem 2048'),
  },
  {
    description: 'gpg --output .claude/skills/x.gpg → deny',
    expect: 'deny',
    event: bash('gpg --output .claude/skills/x.gpg --encrypt foo'),
  },

  // --- dd of= ---
  {
    description: 'dd of=.claude/settings.json → deny',
    expect: 'deny',
    event: bash('dd if=/dev/stdin bs=64 count=1 of=.claude/settings.json'),
  },
  {
    description: 'dd if=foo of=.claude/hooks/x → deny',
    expect: 'deny',
    event: bash('dd if=foo of=.claude/hooks/x'),
  },

  // --- tar -C dest ---
  {
    description: 'tar xf evil.tar -C .claude/ → deny',
    expect: 'deny',
    event: bash('tar xf evil.tar -C .claude/'),
  },
  {
    description: 'tar -xf evil.tar -C .claude/hooks/ → deny',
    expect: 'deny',
    event: bash('tar -xf evil.tar -C .claude/hooks/'),
  },

  // --- unzip -d dest ---
  {
    description: 'unzip evil.zip -d .claude/ → deny',
    expect: 'deny',
    event: bash('unzip evil.zip -d .claude/'),
  },
  {
    description: 'unzip -o evil.zip -d .claude/skills/ → deny',
    expect: 'deny',
    event: bash('unzip -o evil.zip -d .claude/skills/'),
  },

  // --- install ---
  {
    description: 'install -m 0644 src .claude/settings.json → deny',
    expect: 'deny',
    event: bash('install -m 0644 evil.json .claude/settings.json'),
  },

  // --- ssh-keygen -f ---
  {
    description: 'ssh-keygen -f .claude/hooks/key → deny',
    expect: 'deny',
    event: bash('ssh-keygen -t ed25519 -f .claude/hooks/key -N ""'),
  },

  // --- awk -i inplace ---
  {
    description: 'awk -i inplace targeting .claude/settings.json → deny',
    expect: 'deny',
    event: bash('awk -i inplace \'{gsub(/x/,"y")}1\' .claude/settings.json'),
  },

  // --- yq -i ---
  {
    description: 'yq -i targeting .claude/settings.json → deny',
    expect: 'deny',
    event: bash('yq -i \'.foo = "bar"\' .claude/settings.json'),
  },

  // --- gawk -i inplace (GNU awk binary - v5 audit MEDIUM) ---
  {
    description: 'gawk -i inplace targeting .claude/settings.json → deny',
    expect: 'deny',
    event: bash('gawk -i inplace \'{gsub(/x/,"y")}1\' .claude/settings.json'),
  },

  // --- Windows del / Remove-Item / rd extraction (v5 audit MEDIUM) ---
  // When rm category is overridden to allow, path-based checks must still fire.
  {
    description: 'Remove-Item .claude/settings.json (rm:allow) → deny via settings-write',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: 'allow' } },
    event: { tool_name: 'Bash', tool_input: { command: 'Remove-Item .claude/settings.json' } },
  },
  {
    description: 'del .claude/settings.json (rm:allow) → deny via settings-write',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: 'allow' } },
    event: { tool_name: 'Bash', tool_input: { command: 'del .claude\\settings.json' } },
  },
  {
    description: 'ri .claude/settings.json (rm:allow) → deny via settings-write',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: 'allow' } },
    event: { tool_name: 'Bash', tool_input: { command: 'ri .claude/settings.json' } },
  },
  {
    description: 'rd /s .claude (rm:allow) → deny via settings-write',
    expect: 'deny',
    guardrailsConfig: { categories: { rm: 'allow' } },
    event: { tool_name: 'Bash', tool_input: { command: 'rd /s .claude' } },
  },

  // --- False-positive safety: extraction must NOT fire on quoted strings ---
  {
    description: 'echo "sed -i .claude/settings.json" → allow (string literal)',
    expect: 'allow',
    event: bash('echo "sed -i .claude/settings.json"'),
  },

  // --- safe sed/perl outside .claude/ → no settings-write match → allow ---
  {
    description: 'sed -i /tmp/file → allow (no protected path)',
    expect: 'allow',
    event: bash('sed -i s/x/y/ /tmp/file'),
  },
];
