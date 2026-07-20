'use strict';

// Standard git category cases - no -C flag, plain commands.
// cwd is set to a neutral dir that is never inside HOME/.claude.

const CWD = 'C:\\Workspace\\myproject';

function bash(command) {
  return { tool_name: 'Bash', tool_input: { command }, cwd: CWD };
}

module.exports = [
  // git-stash
  { description: 'git stash',               expect: 'deny', event: bash('git stash') },
  { description: 'git stash pop',            expect: 'deny', event: bash('git stash pop') },
  { description: 'git stash drop',           expect: 'deny', event: bash('git stash drop') },

  // git-reset
  { description: 'git reset --hard',         expect: 'deny', event: bash('git reset --hard HEAD') },
  { description: 'git reset --mixed',        expect: 'deny', event: bash('git reset --mixed HEAD~1') },
  { description: 'git reset HEAD',           expect: 'deny', event: bash('git reset HEAD') },

  // git-push-force (must match before git-push)
  { description: 'git push --force',         expect: 'deny', event: bash('git push origin main --force') },
  { description: 'git push -f',              expect: 'deny', event: bash('git push origin main -f') },
  { description: 'git push --force-with-lease', expect: 'deny', event: bash('git push --force-with-lease') },

  // git-push
  { description: 'git push (plain)',         expect: 'deny', event: bash('git push') },
  { description: 'git push origin main',     expect: 'deny', event: bash('git push origin main') },

  // git-commit
  { description: 'git commit -m',            expect: 'ask',  event: bash('git commit -m "fix"') },
  { description: 'git commit --amend',       expect: 'ask',  event: bash('git commit --amend') },

  // git-clean
  { description: 'git clean -fd',            expect: 'deny', event: bash('git clean -fd') },
  { description: 'git clean -fdx',           expect: 'deny', event: bash('git clean -fdx') },

  // git-restore
  { description: 'git restore .',            expect: 'deny', event: bash('git restore .') },
  { description: 'git checkout -- .',        expect: 'deny', event: bash('git checkout -- .') },
  { description: 'git checkout main -- file',expect: 'deny', event: bash('git checkout main -- src/file.js') },

  // git-revert
  { description: 'git revert HEAD',          expect: 'deny', event: bash('git revert HEAD') },

  // git-branch-delete
  { description: 'git branch -d',            expect: 'deny', event: bash('git branch -d my-branch') },
  { description: 'git branch -D',            expect: 'deny', event: bash('git branch -D my-branch') },
  { description: 'git branch --delete',      expect: 'deny', event: bash('git branch --delete my-branch') },
  { description: 'git push --delete branch', expect: 'deny', event: bash('git push origin --delete my-branch') },
];
