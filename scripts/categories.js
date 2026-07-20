'use strict';

// Each category has:
//   patterns    - array of RegExp tested against the full command string
//   description - short label used in logs
//   message     - human/agent-facing explanation shown when the decision fires
const CATEGORIES = {
  'git-stash': {
    description: 'Git stash',
    defaultDecision: 'deny',
    patterns: [
      // deny all stash ops EXCEPT the read-only ones (list, show)
      /git\s+(?:\S+\s+)*stash(?!\s+(?:list|show)\b)/i,
    ],
    message: `DESTRUCTIVE GIT OPERATION - git stash

You are attempting to stash changes in the working tree.

This action may result in:
  • Hidden changes that are easy to forget about
  • Conflicts when multiple agents or sessions pop the stash
  • Data loss if the stash is dropped or overwritten

Use these alternatives instead:
  • Read the current state with: git status, git diff, git log
  • Work directly on the files without hiding changes
  • If you need to see another branch's content: git show <branch>:<file>`,
  },

  'git-reset': {
    description: 'Git reset (hard/mixed)',
    defaultDecision: 'deny',
    patterns: [
      // all forms of reset are destructive (--hard, --mixed, --soft, --keep, --merge, bare)
      /git\s+(?:\S+\s+)*reset\b/i,
    ],
    message: `DESTRUCTIVE GIT OPERATION - git reset

You are attempting to reset the repository state.

This action may result in:
  • Loss of uncommitted changes in tracked files
  • Rewriting of the index or working tree
  • Potential data loss if changes have not been committed

Use these alternatives instead:
  • Read what changed: git log, git diff, git show <commit>
  • Edit files directly to revert specific changes
  • To unstage a file: git restore --staged <file> (ask the user to run: ! git restore --staged <file>)
  • If reset is truly the only way forward, explain to the user WHY it is unavoidable
    and ask them to run: ! git reset <options>`,
  },

  'git-push-force': {
    description: 'Git force push',
    defaultDecision: 'deny',
    patterns: [
      /git\s+(?:\S+\s+)*push\s+.*--force/i,
      // -f alone or bundled with other short flags (-fv, -fn, -fq, etc.)
      /git\s+(?:\S+\s+)*push\s+.*-f[a-zA-Z]*(?:\s|$)/i,
      /git\s+(?:\S+\s+)*push\s+.*--force-with-lease/i,
      // --mirror overwrites all remote refs unconditionally (equivalent to --force-all).
      /git\s+(?:\S+\s+)*push\s+.*--mirror\b/i,
    ],
    message: `DESTRUCTIVE GIT OPERATION - git push --force

You are attempting to force-push to a remote branch.

This action may result in:
  • Overwriting commits on the remote that others may have based work on
  • Permanent loss of remote history
  • Breaking other contributors' local branches

If force-push is truly the only way forward, provide a solid justification to the user
explaining exactly why it is necessary and what history will be overwritten, then ask them
to run: ! git push --force  (or --force-with-lease for a safer variant)`,
  },

  'git-push': {
    description: 'Git push',
    defaultDecision: 'deny',
    patterns: [
      /git\s+(?:\S+\s+)*push\b/i,
    ],
    message: `GIT REMOTE OPERATION - git push

You are attempting to push commits to a remote repository.

This action will:
  • Publish local commits to the remote branch
  • Make changes visible to other contributors

There is no alternative - pushing requires user intent. Provide a clear summary of what
commits will be published, then ask the user to run: ! git push`,
  },

  'git-clone': {
    description: 'Git clone / submodule / subtree add',
    defaultDecision: 'deny',
    patterns: [
      /git\s+(?:\S+\s+)*clone\b/i,
      // submodule add and subtree add both write files into the destination directory
      /git\s+(?:\S+\s+)*submodule\s+add\b/i,
      /git\s+(?:\S+\s+)*subtree\s+add\b/i,
    ],
    message: `GIT OPERATION - git clone

You are attempting to clone a remote repository.

This action may result in:
  • Planting malicious files into .claude/hooks/, .claude/skills/, or .claude/commands/
    if the destination is inside the project's Claude configuration directory
  • Introducing untrusted code into the project silently

Use these alternatives instead:
  • Inspect the remote repo first: read its README or files via the browser
  • If cloning is truly necessary, provide a clear summary of what will be cloned and where,
    then ask the user to run: ! git clone <url> [<dir>]`,
  },

  'git-commit': {
    description: 'Git commit',
    defaultDecision: 'ask',
    patterns: [
      /git\s+(?:\S+\s+)*commit\b/i,
    ],
    message: `GIT OPERATION - git commit

You are attempting to create a new commit.

Committing requires explicit user intent. Summarize what changes will be committed and why,
then ask the user to run: ! git commit -m "<message>"`,
  },

  'git-clean': {
    description: 'Git clean / history rewrite',
    defaultDecision: 'deny',
    patterns: [
      /git\s+(?:\S+\s+)*clean\b/i,
      // worktree remove/prune delete the worktree directory and can lose uncommitted work
      /git\s+(?:\S+\s+)*worktree\s+(?:remove|prune)\b/i,
      // history rewrite - more destructive than git reset (all branches/refs affected).
      // filter-branch: rewrites arbitrary commits; filter-repo: modern replacement, same risk.
      /git\s+(?:\S+\s+)*filter-branch\b/i,
      /git\s+(?:\S+\s+)*filter-repo\b/i,
    ],
    message: `DESTRUCTIVE GIT OPERATION - git clean

You are attempting to remove untracked files from the working tree.

This action may result in:
  • Permanent deletion of untracked files and directories
  • Loss of work that was not yet staged or committed

Use this alternative first:
  • List what would be deleted without deleting: git clean -n
If deletion is truly necessary, provide a solid justification and ask the user to run:
  ! git clean -fd`,
  },

  'git-restore': {
    description: 'Git restore / checkout file',
    defaultDecision: 'deny',
    patterns: [
      /git\s+(?:\S+\s+)*restore\b/i,
      // checkout used to restore files (discards working tree changes)
      /git\s+(?:\S+\s+)*checkout\s+--\s+/i,
      /git\s+(?:\S+\s+)*checkout\s+\S+\s+--\s+/i,
      // switch --detach and --discard-changes also discard working tree
      /git\s+(?:\S+\s+)*switch\s+.*--(?:detach|discard-changes)\b/i,
    ],
    message: `DESTRUCTIVE GIT OPERATION - git restore

You are attempting to discard working tree changes.

This action may result in:
  • Permanent loss of uncommitted modifications to tracked files
  • No way to recover discarded changes

Use these alternatives instead:
  • Read the current content: git diff <file>, git show HEAD:<file>
  • Edit the file directly to revert specific lines
If discarding is truly necessary, provide a solid justification and ask the user to run:
  ! git restore <file>`,
  },

  'git-revert': {
    description: 'Git revert',
    defaultDecision: 'deny',
    patterns: [
      /git\s+(?:\S+\s+)*revert\b/i,
    ],
    message: `GIT OPERATION - git revert

You are attempting to create a revert commit.

This action will:
  • Create a new commit that undoes a previous commit
  • Rewrite the effective state of affected files

Use these alternatives instead:
  • Read what the commit changed: git show <commit>
  • Edit the affected files directly to undo the changes
If a revert commit is truly necessary, provide a solid justification and ask the user to run:
  ! git revert <commit>`,
  },

  'git-branch-delete': {
    description: 'Git branch delete',
    defaultDecision: 'deny',
    patterns: [
      /git\s+(?:\S+\s+)*branch\s+.*-[dD]\b/i,
      /git\s+(?:\S+\s+)*branch\s+.*--delete\b/i,
      /git\s+(?:\S+\s+)*push\s+.*--delete\b/i,
      // Colon-refspec delete: `git push origin :branch` pushes empty → deletes remote branch.
      // Caught by git-push by default, but if git-push is set to "allow", branch-delete must
      // still fire because deleting a branch is more destructive than a normal push.
      // `(?:\S+\s+)+` (one-or-more) before `:[^\s]` absorbs flags + remote so that
      // `git push -u origin :main` or `git push --tags origin :feature` are caught.
      /git\s+(?:\S+\s+)*push\s+(?:\S+\s+)+:[^\s]/i,
    ],
    message: `DESTRUCTIVE GIT OPERATION - git branch delete

You are attempting to delete a branch.

This action may result in:
  • Loss of commits reachable only from that branch
  • Broken references for other contributors

If branch deletion is truly necessary, provide a solid justification (confirm the branch
is fully merged or no longer needed), then ask the user to run:
  ! git branch -d <name>`,
  },

  'rm': {
    description: 'File removal',
    defaultDecision: 'deny',
    patterns: [
      // Exclude `npm rm` / `yarn rm` - package removal, not filesystem deletion
      // Require rm to appear as a command token: start of string, after a shell
      // separator (`&&`, `||`, `;`, `|`, `(`, `{`, backtick, `$(`, newline/CR),
      // optionally with `sudo`/`env` and an optional backslash-escape `\rm`.
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:sudo\s+)?(?:env\s+(?:\S+\s+)*)?\\?rm\b/,
      // xargs invocation of rm/unlink: `... | xargs rm` / `... | xargs unlink`
      /\bxargs\b(?:\s+-\S+)*\s+\\?(?:rm|unlink)\b/,
      // bash/sh -c "rm ..." - rm inside a -c argument
      /\b(?:ba)?sh\s+(?:\S+\s+)*-c\s+['"]?[^'"]*\brm\b/i,
      // find -exec rm / find -execdir rm - rm as argument to find's -exec flag.
      // Allow an optional absolute path prefix before rm (/bin/rm, /usr/bin/rm).
      /\bfind\b[^|&;]*-exec(?:dir)?\s+(?:[^\s|&;]*\/)?\\?rm\b/i,
      // find -delete - find's built-in deletion flag, no rm invocation needed.
      // Require command-position anchor so that "some-tool find-artifacts --delete-orphans"
      // does not fire: (1) `find` must appear as a command token, and (2) `-delete` must
      // be a standalone flag (not part of `--delete-*` compound flags).
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:sudo\s+)?find\b[^|&;]*\s-delete\b(?!-)/i,
      // shred - secure overwrite/delete, bypasses rm if not explicitly caught.
      // Require command-position to avoid false positives in arguments.
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:sudo\s+)?shred\b/,
      // unlink - POSIX single-file deletion (unlink(2) syscall). No flags.
      // Require command-position anchor to avoid false positives.
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:sudo\s+)?unlink\b/,
      // Windows
      /\bdel\b/i,
      /\brmdir\b/i,
      // Windows rd (short alias for rmdir), only when followed by /s to avoid false positives
      /\brd\s+\/s\b/i,
      // PowerShell
      /Remove-Item\b/i,
      // ri is the PowerShell alias for Remove-Item. Require command-position
      // to avoid false-firing on Unix flags like `grep -ri`, `sort -ri`,
      // `ls -ri` (where -ri is a flag bundle, not a command).
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*ri\s+/,
    ],
    message: `DESTRUCTIVE FILE OPERATION - rm / del / Remove-Item

You are attempting to delete files or directories.

This action may result in:
  • Permanent loss of files (especially with -rf / -Recurse)
  • No recovery path outside of git history

Use these alternatives instead:
  • Move to a temp location instead of deleting (reversible)
  • Use the Edit or Write tool to clear the file content without deleting
  • Check if the file is still needed by reading it first
If deletion is truly the only way forward, provide a solid justification explaining
why the file must be deleted, then ask the user to run:
  ! rm "<path>"              (for a file)
  ! rm -rf "<path>"          (for a directory)`,
  },

  'ln': {
    description: 'Symlink / hard-link creation',
    defaultDecision: 'deny',
    patterns: [
      // Unix ln at command-position (avoid false positives in echoed strings).
      // Catches: ln, ln -s, ln --symbolic, ln -sf, ln /src /dst (hard link).
      // Also accepts a sudo prefix: `sudo ln -s ...`.
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:sudo\s+)?ln\b/,
      // Windows mklink (creates symbolic, hard, or junction links).
      /\bmklink\b/i,
      // PowerShell New-Item with link types - accept both -ItemType and its
      // -Type alias (PowerShell 5.0+).
      /New-Item\b[^|;&]*-(?:ItemType|Type)\s+(?:SymbolicLink|HardLink|Junction)\b/i,
    ],
    message: `SYMLINK / HARD-LINK CREATION

You are attempting to create a symlink or hard link. This can be used to bypass
path-based protections (an agent can plant a symlink inside .claude/ pointing
to a file outside, then write through the symlink to escape the guardrails).

If this is intentional, the user can explicitly allow it by setting
"ln": "allow" in .claude/guardrails.json. Otherwise, prefer regular file
operations (cp, mv) over linking.`,
  },

  'kill': {
    description: 'Process kill',
    defaultDecision: 'ask',
    patterns: [
      // Unix - numeric signal forms
      /\bkill\s+-\d+/,
      /\bkill\s+\d+/,
      // Unix - signal-name forms: kill -TERM, kill -KILL, kill -SIGTERM, etc.
      /\bkill\s+-(?:SIG)?(?:TERM|KILL|HUP|INT|QUIT|ABRT|STOP|USR[12]|CONT|ALRM|PIPE|CHLD|SEGV|TSTP)\b/i,
      /\bpkill\b/i,
      /\bkillall\b/i,
      // Windows native
      /\btaskkill\b/i,
      /\bwmic\b.*\bprocess\b.*(delete|terminate)/i,
      // PowerShell
      /Stop-Process\b/i,
      /\bspps\s/i,
      /Remove-Process\b/i,
      /Get-Process.*Stop-Process/i,
      /pwsh.*Stop-Process/i,
      /powershell.*Stop-Process/i,
      /pwsh.*\bkill\b/i,
      /powershell.*\bkill\b/i,
      // Service control
      /\bnet\s+stop\b/i,
      /\bsc\s+stop\b/i,
      /\bsc\.exe\s+stop\b/i,
      // Pipeline kill patterns
      /netstat.*taskkill/i,
      /Get-NetTCPConnection.*Stop-Process/i,
      /for\s+\/f.*taskkill/i,
      // Node-based port killers
      /npx\s+kill-port/i,
      /npm\s+.*kill-port/i,
      /node.*kill.*port/i,
      // PSTools
      /\bpskill\b/i,
      // Script-based kill
      /cscript.*kill/i,
      /wscript.*kill/i,
    ],
    message: `PROCESS TERMINATION - kill / taskkill / Stop-Process

You are attempting to terminate a running process.

This action may result in:
  • Loss of unsaved data in the terminated application
  • Interrupted connections or services
  • Potential instability if a critical process is affected

If terminating the process is truly necessary, provide a solid justification (which process,
why it must be stopped, what impact is expected), then ask the user to run:
  ! taskkill /PID <pid> /F`,
  },

  'chmod': {
    description: 'Permission change',
    defaultDecision: 'deny',
    patterns: [
      /\bchmod\b/i,
      /\bchown\b/i,
      // PowerShell / Windows ACL
      /Set-Acl\b/i,
      /icacls\b/i,
      /cacls\b/i,
    ],
    message: `PERMISSION CHANGE - chmod / chown / icacls

You are attempting to modify file permissions or ownership.

This action may result in:
  • Security exposure if permissions are broadened unintentionally
  • Access issues if permissions are restricted too aggressively

If the permission change is truly necessary, provide a solid justification (which file,
what permission is needed and why), then ask the user to run:
  ! icacls "<path>" /grant "<user>:<permission>"`,
  },

  'docker-rm': {
    description: 'Docker destructive',
    defaultDecision: 'deny',
    patterns: [
      /\bdocker\s+rm\b/i,
      /\bdocker\s+rmi\b/i,
      // fully-qualified object form: docker volume rm, docker container rm, docker image rm
      /\bdocker\s+(?:volume|container|image|network)\s+rm\b/i,
      /\bdocker\s+system\s+prune\b/i,
      /\bdocker\s+container\s+prune\b/i,
      /\bdocker\s+image\s+prune\b/i,
      /\bdocker\s+volume\s+prune\b/i,
      /\bdocker\s+network\s+prune\b/i,
      /\bdocker\s+compose\s+down\b/i,
      /\bdocker-compose\s+down\b/i,
    ],
    message: `DESTRUCTIVE DOCKER OPERATION - docker rm / rmi / prune

You are attempting to remove Docker containers, images, volumes, or networks.

This action may result in:
  • Loss of container data not backed by a volume
  • Deletion of locally built images requiring a full rebuild
  • Removal of persistent volumes and their data

Use these alternatives first:
  • Inspect before removing: docker ps -a, docker images, docker volume ls
  • Stop a container without removing it: docker stop <name>
If removal is truly necessary, provide a solid justification, then ask the user to run:
  ! docker rm <name>   or   ! docker rmi <image>`,
  },

  'drop-db': {
    description: 'Database drop/truncate',
    defaultDecision: 'deny',
    patterns: [
      /\bDROP\s+(TABLE|DATABASE|SCHEMA|KEYSPACE)\b/i,
      /\bTRUNCATE\s+TABLE\b/i,
      /\bDELETE\s+FROM\b/i,
      // Redis: FLUSHALL wipes all DBs, FLUSHDB wipes current DB.
      /\bFLUSHALL\b/i,
      /\bFLUSHDB\b/i,
      // MongoDB shell: db.dropDatabase(), db.<collection>.drop()
      /\bdb\.dropDatabase\s*\(/i,
      /\bdb\.\w+\.drop\s*\(/i,
    ],
    message: `DESTRUCTIVE DATABASE OPERATION - DROP / TRUNCATE / DELETE

You are attempting to drop or truncate database objects.

This action may result in:
  • Permanent loss of all data in the affected table, schema, or database
  • No recovery path without a prior backup

If this is truly necessary, ask the user to run the statement directly:
  ! <your SQL statement>`,
  },

  'format-disk': {
    description: 'Disk format / low-level write',
    defaultDecision: 'deny',
    patterns: [
      /\bmkfs\b/i,
      // Only match standalone `format` as a command (e.g. Windows FORMAT C:), not flags like --format
      /(?:^|&&|\|\||;)\s*format\b/i,
      // dd writing to a device
      /\bdd\b.*\bif=.*\bof=\/dev\//i,
      /\bdd\b.*\bof=\/dev\//i,
      // Windows diskpart
      /\bdiskpart\b/i,
    ],
    message: `DESTRUCTIVE DISK OPERATION - mkfs / format / dd / diskpart

You are attempting a low-level disk or filesystem operation.

This action may result in:
  • Complete and irreversible destruction of all data on the target device
  • Rendering the system unbootable

If this is truly necessary, ask the user to run the command directly:
  ! <your command>`,
  },

  'eval': {
    description: 'Dynamic code execution',
    defaultDecision: 'deny',
    patterns: [
      // eval anywhere except agent-browser eval - strip all agent-browser eval instances first,
      // then block if any standalone eval remains (prevents multi-eval bypass).
      // Uses `stripped` (echo-args removed) to avoid false positives from `echo "eval ..."`.
      (_cmd, stripped) => {
        if (!/\beval\b/.test(stripped)) return false;
        const withoutAgentBrowser = stripped.replace(/(?:^|[\s;|&`(])agent-browser\s+eval\b/g, '');
        return /\beval\b/.test(withoutAgentBrowser);
      },
      // exec with any argument; require command-position separator to avoid
      // false positives like `echo "exec done"`. Exclude shell fd redirections.
      // Also covers `builtin exec` and `command exec` (bypass attempts using bash
      // built-in resolution bypass keywords - both forms replace the current shell).
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:(?:builtin|command)\s+)?exec\s+(?![\d<>])\S/i,
      // echo/printf piped to a shell interpreter through any number of intermediates.
      // Covers: direct (`echo x | sh`), one-hop (`echo x | tee f | sh`), N-hop, etc.
      // Shell prefix: any path prefix `(?:[^\s|&;]*/)?` so that non-standard install
      // paths like /opt/homebrew/bin/bash, /snap/bin/zsh, ~/.local/bin/bash are caught.
      // Also covers xargs acting as a shell executor (xargs -I{} sh -c {}).
      // (?:env\s+(?:\S+\s+)*)? absorbs `env -i`, `env --ignore-environment`, etc.
      /\b(?:echo|printf|print)\b[^|&;]*(?:\|[^|&;]*)*\|\s*(?:[^\s|&;]*\/)?(?:env\s+(?:\S+\s+)*)?(?:(?:ba|z|da|k)?sh|fish)\b/i,
      /\b(?:echo|printf|print)\b[^|&;]*(?:\|[^|&;]*)*\|\s*xargs\b[^|&;]*(?:(?:ba|z|da|k)?sh|fish)\b/i,
      // source / dot-source from absolute non-project paths:
      //   /tmp/, /dev/, /proc/, /sys/ - common piped-payload paths
      //   ~/  - home-relative scripts outside the project
      //   /etc/, /usr/, /opt/, /home/, /root/ - system/user paths
      // Relative paths (./foo, ../foo, plain name) are allowed - they reference
      // project files and are safe to source for local tooling (e.g. `source .env`).
      // Uses stripped (via lambda) so echo "source /tmp/..." doesn't false-fire.
      // The eval category normally uses testCmd=command (because patterns[0] is a
      // function). Source/dot patterns don't need the original - they work on stripped.
      (_cmd, stripped) => /\bsource\s+(?:\/(?:tmp|dev|proc|sys|etc|usr|opt|home|root|var|run)\b|~\/|\$(?:\{(?:HOME|USERPROFILE)\}|HOME|USERPROFILE)(?:\/|$))/i.test(stripped),
      (_cmd, stripped) => /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({"'])\s*\.\s+(?:\/(?:tmp|dev|proc|sys|etc|usr|opt|home|root|var|run)\b|~\/|\$(?:\{(?:HOME|USERPROFILE)\}|HOME|USERPROFILE)(?:\/|$))/i.test(stripped),
      // source/dot with process substitution <(cmd): the runtime path is a /dev/fd/N
      // descriptor, but the literal <( is the tell - any sourced process substitution
      // executes dynamic content and must be blocked.
      (_cmd, stripped) => /\bsource\s+<\(/i.test(stripped),
      (_cmd, stripped) => /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({"'])\s*\.\s+<\(/i.test(stripped),
    ],
    message: `DYNAMIC CODE EXECUTION - eval / exec / source

You are attempting to execute dynamically constructed or untrusted shell code.

This action may result in:
  • Execution of attacker-controlled commands
  • Privilege escalation via injected code
  • Difficult-to-audit side effects

Use these alternatives instead:
  • Rewrite the logic as explicit commands without eval/exec
  • If sourcing a config file, read its content with the Read tool instead
  • If running a script, use an explicit interpreter: node script.js`,
  },

  'cron-at': {
    description: 'Persistence via scheduling',
    defaultDecision: 'deny',
    patterns: [
      // crontab - block edit/replace/remove flags, file-argument, and stdin-redirect forms.
      // Allow read-only -l (listing). `crontab file` and `crontab < file` replace the crontab.
      /crontab\s+-(?!l\b)/i,
      /crontab\s+[^-\s]/i,
      // `at` scheduler - numeric times, named times, and POSIX -t form.
      /\bat\s+now\b/i,
      /\bat\s+\d/i,
      /\bat\s+(?:midnight|noon|teatime|tomorrow|next)\b/i,
      // POSIX: at -t [[CC]YY]MMDDhhmm[.ss]
      /\bat\s+-t\s+\d/i,
      // Writing to cron directories (matches actual modifications, not just mentions of "cron")
      /\/etc\/cron[./]/i,
      /\/var\/spool\/cron\//i,
      // Appending to a crontab via redirection: echo "..." >> /var/spool/cron/...
      /echo\s+.*>>\s*\/var\/spool\/cron\//i,
      /echo\s+.*>>\s*\/etc\/cron/i,
    ],
    message: `PERSISTENCE - cron / at scheduler

You are attempting to create or modify a scheduled task.

This action may result in:
  • Persistent execution of commands across reboots or sessions
  • Backdoor-style persistence if used maliciously
  • Hard-to-detect recurring side effects`,
  },

  'systemctl-stop': {
    description: 'Stop/disable system services',
    defaultDecision: 'deny',
    patterns: [
      // Allow global flags (--now, --user, -q, etc.) before the verb.
      /systemctl\s+(?:\S+\s+)*(stop|disable|mask|kill)\b/i,
      /service\s+\S+\s+stop\b/i,
    ],
    message: `SYSTEM SERVICE - systemctl stop / disable / mask

You are attempting to stop or disable a system service.

This action may result in:
  • Loss of availability for the affected service
  • Dependent services or applications breaking
  • System instability if a critical service is affected

Use these alternatives first:
  • Check service status: sc query <service>
  • Read service logs before deciding to stop it
If stopping the service is truly necessary, provide a solid justification, then ask the user
to run: ! net stop <service>`,
  },

  'firewall': {
    description: 'Firewall flush / network rule change',
    defaultDecision: 'deny',
    patterns: [
      // Allow flags (-v, -t table, etc.) before the operative flag (-F/-D/--flush).
      /iptables\s+(?:\S+\s+)*-F\b/i,
      /iptables\s+(?:\S+\s+)*--flush\b/i,
      /iptables\s+(?:\S+\s+)*-D\b/i,
      /ip6tables\s+(?:\S+\s+)*-F\b/i,
      /ip6tables\s+(?:\S+\s+)*--flush\b/i,
      /nft\s+flush\b/i,
      /nft\s+delete\b/i,
      /ufw\s+disable\b/i,
      /netsh\s+advfirewall\s+set.*off/i,
    ],
    message: `FIREWALL MODIFICATION - iptables / nft / ufw / netsh

You are attempting to flush or disable firewall rules.

This action may result in:
  • Full network exposure of the host
  • Loss of all inbound/outbound traffic filtering
  • Permanent rule deletion with no automatic restore`,
  },

  'log-clear': {
    description: 'System log erasure',
    defaultDecision: 'deny',
    patterns: [
      />\s*\/var\/log\//,
      /truncate\s+-s\s*0\s+.*\/log\//i,
      /echo\s+""\s*>\s*.*\/log\//i,
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*rm\s+.*\.log\b/i,
      /Clear-EventLog\b/i,
      /wevtutil\s+cl\b/i,
    ],
    message: `LOG ERASURE - clearing system or application logs

You are attempting to erase log files.

This action may result in:
  • Loss of audit trail and forensic evidence
  • Inability to diagnose past or ongoing incidents
  • Potential compliance violation`,
  },

  'sudo-shell': {
    description: 'Sudo privilege escalation to shell',
    defaultDecision: 'ask',
    patterns: [
      /sudo\s+(su|bash|sh|zsh|fish|dash)\b/i,
      /sudo\s+-s\b/i,
      /sudo\s+-i\b/i,
      /sudo\s+vim\b/i,
      /sudo\s+less\b/i,
      /sudo\s+nano\b/i,
      /sudo\s+awk\b/i,
      /sudo\s+perl\b/i,
      /sudo\s+python\b/i,
    ],
    message: `PRIVILEGE ESCALATION - sudo to interactive shell or editor

You are attempting to open a root shell or run a root-privileged interactive process.

This action may result in:
  • Full root access with no further audit trail
  • Persistent privilege escalation if the shell is left open
  • Unintended system-wide changes`,
  },

  'env-hijack': {
    description: 'Library preload / PATH hijack',
    defaultDecision: 'deny',
    patterns: [
      // export: match dangerous variable anywhere in the assignment list.
      // Multi-assignment forms like `export DUMMY=1 LD_PRELOAD=...` insert innocuous
      // variables first; anchoring to the keyword would miss them.
      /export\b[^|&;\n\r]*\bLD_PRELOAD=/i,
      /export\b[^|&;\n\r]*\bLD_LIBRARY_PATH=/i,
      /export\b[^|&;\n\r]*\bDYLD_INSERT_LIBRARIES=/i,
      // declare/typeset -x: bash/ksh equivalents to `export VAR=`. Require the -x flag
      // because declare/typeset without -x sets a shell-local variable that is never
      // exported to child processes - no preload risk without export semantics.
      /(?:declare|typeset)\b[^|&;\n\r]*-[a-zA-Z]*x[a-zA-Z]*[^|&;\n\r]*\bLD_PRELOAD=/i,
      /(?:declare|typeset)\b[^|&;\n\r]*-[a-zA-Z]*x[a-zA-Z]*[^|&;\n\r]*\bLD_LIBRARY_PATH=/i,
      /(?:declare|typeset)\b[^|&;\n\r]*-[a-zA-Z]*x[a-zA-Z]*[^|&;\n\r]*\bDYLD_INSERT_LIBRARIES=/i,
      // declare/typeset -x PATH= (same three forms as export PATH=)
      /(?:declare|typeset)\s+(?:\S+\s+)*-[a-zA-Z]*x[a-zA-Z]*\s+PATH=\./i,
      // PATH assignment - check EVERY colon-delimited segment for writable dirs.
      // Uses stripped (second arg, echo-args removed) so `echo "export PATH=/tmp:$PATH"`
      // doesn't false-fire. Strip outer quotes from the captured value before splitting
      // so that `export PATH="/tmp/evil:$PATH"` (quoted) is treated the same as unquoted.
      // Curly-brace ${HOME} and ${USERPROFILE} are matched explicitly alongside bare forms.
      (_cmd, stripped) => {
        // Match dangerous segment prefixes. `$HOME` / `${HOME}` accept trailing /, :, or
        // end-of-segment (bare home dir is also user-writable).
        const WRITABLE = /^(?:\/tmp|\/dev\/shm|\/var\/tmp|~(?:[/:]|$)|\$(?:\{(?:HOME|USERPROFILE)\}|HOME|USERPROFILE)(?:[/:]|$)|\/home\/|\.(?:[/:]|$))/;
        const m = stripped.match(/\bPATH=([^\s|&;]+)/);
        if (!m) return false;
        const raw = m[1].replace(/^["']|["']$/g, '');
        for (const seg of raw.split(':')) {
          if (WRITABLE.test(seg)) return true;
        }
        return false;
      },
      // env VAR=val cmd - POSIX env(1) command form. Distinct from BV-NEW-03 (inline
      // assignment without keyword). Requires command-position anchor to avoid false
      // positives inside echo strings.
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*env\b[^|&;]*\bLD_PRELOAD=/i,
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*env\b[^|&;]*\bLD_LIBRARY_PATH=/i,
      /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*env\b[^|&;]*\bDYLD_INSERT_LIBRARIES=/i,
    ],
    message: `ENVIRONMENT HIJACK - LD_PRELOAD / PATH injection

You are attempting to inject a library or hijack the executable search path.

This action may result in:
  • Arbitrary code injection into every subsequently spawned process
  • Credential theft or privilege escalation via hijacked binaries
  • Hard-to-detect persistence mechanism`,
  },

  'python': {
    description: 'Python runtime / package manager',
    defaultDecision: 'deny',
    patterns: [
      // Python interpreter: python, python3, python3.11, etc.
      /\bpython(?:\d+(?:\.\d+)?)?\b/i,
      // Windows py launcher (https://docs.python.org/3/using/windows.html#launcher): py -3, py script.py
      // Intentionally requires a trailing space to avoid false positives (e.g. `mypy`, `copy`)
      /\bpy\s/i,
      // pip package manager: pip, pip3, pip2
      /\bpip(?:\d+)?\b/i,
      // Conda (Anaconda / Miniconda)
      /\bconda\b/i,
      // pipenv virtual environment manager
      /\bpipenv\b/i,
      // poetry Python package manager
      /\bpoetry\b/i,
      // virtualenv
      /\bvirtualenv\b/i,
      // pyenv Python version manager
      /\bpyenv\b/i,
      // pytest test runner
      /\bpytest\b/i,
      // uv modern Python package manager (astral-sh/uv)
      /\buv\s+(pip|run|sync|add|venv|tool|python)\b/i,
    ],
    message: `PYTHON NOT ALLOWED - python / pip / conda / poetry / virtualenv

Python is not accepted on this machine. Use Node.js alternatives instead:
  • Replace Python scripts with Node.js scripts
  • Use npm packages instead of pip packages
  • Use node for scripting, data processing, and automation`,
  },
};

/**
 * Returns ALL matched category objects [{ name, ...def }, ...] sorted by most restrictive
 * decision first (deny > ask > allow). Returns [] if nothing matched.
 * Only tests categories whose names are in the provided list.
 *
 * Why all matches: a command can satisfy multiple categories (e.g. `git push --force` matches
 * both git-push-force and git-push). Returning only the first match by insertion order meant
 * that an 'allow' override on a less-specific category silently suppressed a 'deny' on a more
 * specific one. Callers must now pick the most restrictive decision across all matches.
 */

// Strips the quoted string arguments of echo/printf/print to prevent false positives
// where a dangerous pattern (e.g. `git reset`) appears inside an echo message.
// Only strips the literal argument strings; the command structure itself is preserved.
// This mirrors the agent-browser eval strip in the eval category.
//
// IMPORTANT: Only strip args that contain NO command substitution `$(` or backtick.
// `echo "$(rm -rf x)"` contains a real command inside the quote - stripping it would
// hide the rm from category detection. Keep these args intact so categories can fire.
// The false-positive concern only applies to pure-literal strings.
function stripEchoArgs(cmd) {
  // Strip ALL consecutive quoted arguments after an echo/printf/print keyword.
  // The first-arg-only approach missed `printf '%s\n' 'git stash'` where the format
  // string '%s\n' is stripped but the literal payload 'git stash' remains visible.
  // We iterate removing one quoted arg at a time until no more literal (non-$()) args follow.
  let prev;
  let result = cmd;
  do {
    prev = result;
    result = result
      .replace(/\b(?:echo|printf|print)\b([^|&;\n\r]*?)\s+"([^"]*)"/gi, (full, before, inner) =>
        /\$\(|`/.test(inner) ? full : `echo${before}`)
      .replace(/\b(?:echo|printf|print)\b([^|&;\n\r]*?)\s+\$'([^']*)'/gi, (full, before, inner) =>
        /\$\(|`/.test(inner) ? full : `echo${before}`)
      .replace(/\b(?:echo|printf|print)\b([^|&;\n\r]*?)\s+'([^']*)'/gi, (full, before, inner) =>
        /\$\(|`/.test(inner) ? full : `echo${before}`);
  } while (result !== prev);
  return result;
}

function matchCategory(command, categoryNames) {
  const stripped = stripEchoArgs(command);
  const matches = [];
  for (const name of categoryNames) {
    const def = CATEGORIES[name];
    if (!def) continue;
    // The eval category's first pattern is a lambda (manages agent-browser stripping).
    // Its RegExp patterns (pipe-to-shell) are tested on the ORIGINAL command because
    // stripEchoArgs removes the echo keyword, making `\b(?:echo|printf)\b` fail on
    // stripped. All other categories use stripped to suppress echo false-positives.
    // All lambdas receive both (command, stripped) so they can choose their input.
    const testCmd = typeof def.patterns[0] === 'function' ? command : stripped;
    const hit = def.patterns.some((p) => {
      if (typeof p === 'function') return p(command, stripped);
      if (p instanceof RegExp) return p.test(testCmd);
      return false;
    });
    if (hit) matches.push({ name, ...def });
  }
  return matches;
}

module.exports = { CATEGORIES, matchCategory };
