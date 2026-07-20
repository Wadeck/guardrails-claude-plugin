'use strict';

// False-positive guard - commands that must NOT trigger any guardrail.
// If any of these are blocked the plugin is over-aggressive.

const CWD = 'C:\\Workspace\\myproject';

function bash(command) {
  return { tool_name: 'Bash', tool_input: { command }, cwd: CWD };
}

module.exports = [
  // Regular git commands
  { description: 'git status',               expect: 'allow', event: bash('git status') },
  { description: 'git log',                  expect: 'allow', event: bash('git log --oneline -10') },
  { description: 'git diff',                 expect: 'allow', event: bash('git diff HEAD') },
  { description: 'git fetch',                expect: 'allow', event: bash('git fetch origin') },
  { description: 'git pull',                 expect: 'allow', event: bash('git pull') },
  { description: 'git checkout branch',      expect: 'allow', event: bash('git checkout my-branch') },
  { description: 'git branch (list)',        expect: 'allow', event: bash('git branch -a') },
  { description: 'git add',                  expect: 'allow', event: bash('git add src/file.js') },
  { description: 'git stash list',           expect: 'allow', event: bash('git stash list') },
  { description: 'git stash show',           expect: 'allow', event: bash('git stash show') },

  // npm / node - should not trigger rm pattern
  { description: 'npm rm package',           expect: 'allow', event: bash('npm rm lodash') },
  { description: 'yarn rm package',          expect: 'allow', event: bash('yarn rm lodash') },
  { description: 'npm install',              expect: 'allow', event: bash('npm install') },
  { description: 'node script.js',           expect: 'allow', event: bash('node scripts/build.js') },

  // File reads
  { description: 'cat file',                 expect: 'allow', event: bash('cat src/index.js') },
  { description: 'ls directory',             expect: 'allow', event: bash('ls -la src/') },
  { description: 'grep in files',            expect: 'allow', event: bash('grep -r "TODO" src/') },

  // Non-destructive writes outside .claude
  { description: 'echo to project file',     expect: 'allow', event: bash('echo hello > C:\\Workspace\\myproject\\out.txt') },
  { description: 'cp within project',        expect: 'allow', event: bash('cp src/a.js src/b.js') },

  // Write tool to project file (not .claude)
  { description: 'Write to project file',    expect: 'allow', event: { tool_name: 'Write', tool_input: { file_path: 'C:\\Workspace\\myproject\\src\\index.js', content: 'x' }, cwd: CWD } },
  { description: 'Edit project file',        expect: 'allow', event: { tool_name: 'Edit',  tool_input: { file_path: 'C:\\Workspace\\myproject\\src\\index.js', old_string: 'a', new_string: 'b' }, cwd: CWD } },

  // Words that look dangerous but aren't
  { description: 'echo containing "rm"',     expect: 'allow', event: bash('echo "no rm here please"') },
  { description: 'variable named format',    expect: 'allow', event: bash('echo --format=json') },

  // eval only safe as direct subcommand of agent-browser (single and double space)
  { description: 'agent-browser eval',            expect: 'allow', event: bash('agent-browser eval "JSON.stringify(Object.entries(localStorage))"') },
  { description: 'agent-browser eval doublespace', expect: 'allow', event: bash('agent-browser  eval "JSON.stringify(localStorage)"') },
];
