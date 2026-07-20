'use strict';

// git -C <dir> <subcommand> bypass - the bug discovered in wdrive.
// The agent used `git -C /c/Workspace_Tooling/wdrive stash` which previously
// bypassed all guardrails because patterns only matched `git\s+<subcommand>`.

const CWD = 'C:\\Workspace\\myproject';

function bash(command) {
  return { tool_name: 'Bash', tool_input: { command }, cwd: CWD };
}

const DIR = '/c/Workspace_Tooling/wdrive';

module.exports = [
  // git -C <dir> stash
  { description: 'git -C <dir> stash',             expect: 'deny', event: bash(`git -C ${DIR} stash`) },
  { description: 'git -C <dir> stash pop',          expect: 'deny', event: bash(`git -C ${DIR} stash pop`) },

  // git -C <dir> reset
  { description: 'git -C <dir> reset --hard',       expect: 'deny', event: bash(`git -C ${DIR} reset --hard HEAD`) },
  { description: 'git -C <dir> reset --mixed',      expect: 'deny', event: bash(`git -C ${DIR} reset --mixed HEAD~1`) },

  // git -C <dir> push
  { description: 'git -C <dir> push',               expect: 'deny', event: bash(`git -C ${DIR} push`) },
  { description: 'git -C <dir> push --force',       expect: 'deny', event: bash(`git -C ${DIR} push origin main --force`) },
  { description: 'git -C <dir> push -f',            expect: 'deny', event: bash(`git -C ${DIR} push -f`) },

  // git -C <dir> commit
  { description: 'git -C <dir> commit -m',          expect: 'ask',  event: bash(`git -C ${DIR} commit -m "fix"`) },

  // git -C <dir> clean
  { description: 'git -C <dir> clean -fd',          expect: 'deny', event: bash(`git -C ${DIR} clean -fd`) },

  // git -C <dir> restore
  { description: 'git -C <dir> restore .',          expect: 'deny', event: bash(`git -C ${DIR} restore .`) },

  // git -C <dir> revert
  { description: 'git -C <dir> revert HEAD',        expect: 'deny', event: bash(`git -C ${DIR} revert HEAD`) },

  // git -C <dir> branch delete
  { description: 'git -C <dir> branch -d',          expect: 'deny', event: bash(`git -C ${DIR} branch -d old`) },

  // git --git-dir form (less common but same bypass vector)
  { description: 'git --git-dir=... stash',         expect: 'deny', event: bash(`git --git-dir=${DIR}/.git stash`) },
  { description: 'git --git-dir=... push',          expect: 'deny', event: bash(`git --git-dir=${DIR}/.git push`) },
];
