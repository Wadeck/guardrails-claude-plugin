# guardrails threat model

## What this plugin protects against

guardrails runs as a `PreToolUse` hook with a **wildcard matcher** (matches every tool call,
including built-in Bash/Edit/Write/NotebookEdit and all `mcp__*` MCP tools). The script's
`isWriteCapableTool()` helper filters non-write tools (Read, Glob, Grep, etc.) early — only
write-capable tools enter the security-checking pipeline.

The threat model is: **an agent (main or sub-agent) makes a mistake or is manipulated via
prompt injection and issues a destructive or sensitive command without the user realising.**

This is not a security boundary against a determined adversary with full shell access - it is
a safety net against accidental or injected actions.

## Critical Claude Code behavior — `ask` is silently auto-approved under `.claude/`

**Validated empirically 2026-06-21 across 8 controlled tests.** Claude Code does NOT emit a
`PermissionRequest` event for Write/Edit tool calls targeting any file under the project's
`.claude/` directory. A PreToolUse hook returning `permissionDecision: "ask"` for such paths
is silently auto-approved — no dialog, no prompt, the write proceeds.

`deny` and `allow` decisions ARE respected for `.claude/` paths. Only `ask` is broken.

**Consequence enforced in v3-v5:** every rule that targets a path under `.claude/` defaults to
`deny` instead of `ask`. The five self-protection rules (memory-write, guardrails-config-write,
fleet-config-write, settings-write, secrets-file-write) plus `protected_files` user rules
under `.claude/` (which are upgraded ask→deny in `checkProtectedFiles`) all enforce this.

The README "Notes for agents" section documents this caveat for future maintainers.

## Protected categories

| Category | Default | Rationale |
|---|---|---|
| `git-reset` | deny | Discards uncommitted work, hard to recover |
| `git-stash` | deny | Hides changes, creates merge conflicts across sessions |
| `git-push` | deny | Publishes to remote - irreversible visibility |
| `git-push-force` | deny | Can permanently delete remote history; includes `--mirror` (overwrites all remote refs unconditionally, equivalent to `--force` across all refs) |
| `git-commit` | ask | Creates history; user should confirm intent |
| `git-clone` | deny | Clones a remote repository — can plant malicious files into `.claude/hooks/`, `.claude/skills/`, or `.claude/commands/` if the destination is inside the project's Claude config directory; also covers `git submodule add URL DEST` and `git subtree add --prefix=DEST URL REF`; path extractor fires on the destination operand |
| `git-clean` | deny | Deletes untracked files permanently; also covers `git filter-branch`/`git filter-repo` (history rewrite across all refs) |
| `git-restore` | deny | Discards working-tree changes with no undo |
| `git-revert` | deny | Rewrites effective file state |
| `git-branch-delete` | deny | Can lose commits reachable only from that branch |
| `rm` | deny | Permanent file deletion (includes `shred`, `unlink` (POSIX single-file deletion), `find -exec rm`, `find -execdir rm` with absolute or bare paths, `find -delete`, `env -i rm` / `env --ignore-environment rm` — env prefix absorbs arbitrary flags before `rm`; `xargs rm` and `xargs unlink`) |
| `kill` | ask | Terminates processes; numeric (`kill -9`), signal-name (`kill -TERM`, `-SIGTERM`), and word forms covered |
| `chmod` | deny | Security exposure if permissions broadened unintentionally |
| `docker-rm` | deny | Destroys containers, images, volumes |
| `drop-db` | deny | Permanent data loss |
| `format-disk` | deny | Irreversible disk destruction |
| `eval` | deny | Executes dynamically constructed shell code (eval uses `stripped` arg to avoid `echo "eval ..."` false positives; exec/`builtin exec`/`command exec`; echo/printf/print piped to shell through any number of intermediates including tee/cat and xargs-as-executor; shell path prefix is unrestricted; source from absolute/home (`~/`, `$HOME`, `${HOME}`, `$USERPROFILE`)/process-substitution/`/var/`/`/run/` paths; source/dot patterns use `stripped`) |
| `cron-at` | deny | Installs persistence across reboots (named-time and POSIX `-t` at forms; `crontab file` and `crontab < file` file-replace forms; `crontab -l` exempted as read-only; `/etc/cron[./]` prefix covers all standard cron directories including daily/weekly/monthly/reboot) |
| `ln` | deny | Symlink/hard-link/junction creation. Default `deny` because symlinks can bypass path-prefix checks (literal-path defense in checkers also mitigates) |
| `systemctl-stop` | deny | Stops/disables system services (global flags like `--now`, `--user`, `-q` before verb are handled) |
| `firewall` | deny | Flushes or disables network filtering (flags like `-v`, `-t table` before operative flag are handled; `nft delete table/chain/rule` covered alongside `nft flush`) |
| `log-clear` | deny | Erases audit trail (`rm *.log` uses command-position anchor to avoid false positives from `--rm build.log` in tool flag arguments) |
| `sudo-shell` | ask | Opens a root shell with no further audit |
| `env-hijack` | deny | Injects libraries or hijacks executable PATH (`export` searched anywhere in assignment list — `export DUMMY=1 LD_PRELOAD=...` multi-assignment form is caught; `declare`/`typeset` requires `-x` flag since without it the variable is not exported to child processes; env VAR=val cmd; LD_PRELOAD/LD_LIBRARY_PATH/DYLD_INSERT_LIBRARIES and PATH; PATH checked per-segment so dangerous dirs in any position are caught; outer-quoted values stripped; `${HOME}` curly-brace form handled alongside `$HOME`; PATH=., /dev/shm, /tmp, $HOME/, /home/ variants) |
| `python` | deny | Python not installed on this machine |

## Path-based protections

Path-level rules fire on every write-capable tool — Bash, Edit, Write, NotebookEdit, and any
MCP tool whose name matches the write-capable verb-list (`isWriteCapableTool`):

| Rule | Default | What it catches |
|---|---|---|
| `cross-home-write` | deny | Writes into `$HOME/.claude` from a project started outside it |
| `guardrails-config-write` | **deny** | Writes to `.claude/guardrails.json` |
| `memory-write` | **deny** | Writes to `.claude/memory/` |
| `settings-write` | **deny** | Writes to `.claude/settings.json`, `settings.local.json`, `CLAUDE.md`, `hooks/**`, `skills/**`, `commands/**`, or `.claude/` itself |
| `secrets-file-write` | **deny** | Writes to the configured secrets file or any `@`-linked file |
| `secrets-file-access` | deny | Bash commands that reference a secrets file (cat, source, grep, …) |
| `fleet-config-write` | **deny** | Writes to `.claude/w-fleet.json` |

All five `.claude/`-scoped defaults are `deny` because Claude Code silently auto-approves `ask`
for those paths (see "Critical Claude Code behavior" above). Users can opt back in to `ask`
explicitly in `guardrails.json` if they want a prompt for paths outside `.claude/`.

**Symlink defense:** the four most security-critical checkers (settings-write, memory-write,
guardrails-config-write, fleet-config-write) test paths against BOTH the symlink-resolved form
AND the literal form. This prevents a two-step attack where an attacker plants a symlink
inside `.claude/` pointing outside, then writes through the symlink.

**Bash write-path extraction** covers redirections (`>`, `>>`), `tee` (including output
process-substitution form `> >(tee FILE)` — trailing `)` stripped from the token), `sponge`
(moreutils atomic stdin-to-file writer, trailing `)` also stripped), `rsync` (last non-flag
token = destination), `cp`, `mv` (all tokens extracted — covers multi-source form `cp src1 src2 dst`),
`curl -o`, `wget -O`, `rm`/`rmdir`, `shred`, `sed -i` (including `-e`/`-f` script-flag forms),
`perl -pi`, `awk -i inplace` (two-pass extractor: handles script-before-`-i`, script-after-`-i`, `-f script.awk`
external script, and stdin-as-script forms — if only one positional non-flag exists and no `-f`
was seen, it is treated as the target file rather than the inline script), `yq -i`,
`openssl -out`, `gpg --output`, `dd of=`, `tar -C`/`--directory`/`--directory=DIR`/`--one-top-level`/`--one-top-level=DIR` (all forms),
`unzip -d`, `install` (`-t DIR`, `--target-directory DIR`, and `--target-directory=DIR` all
extract `DIR` as the destination instead of the last positional argument), `patch -o`/`--output`,
`ssh-keygen -f`, `truncate -s`/`--size`,
`rsync` (last non-flag token = destination; also extracts `--backup-dir=DIR` and `--backup-dir DIR`
as additional write targets), `sponge` (`-a`/`--append` flag consumed before path extraction),
`curl -o`/`--output` and `curl -oFILE` (concatenated form) and `curl --output-dir DIR` (sets download directory),
`wget -O`/`--output-document` and `wget -OFILE` (concatenated form) and `wget -P DIR`/`--directory-prefix DIR` (sets download directory),
`git clone` (destination operand extracted), `git submodule add URL DEST` (destination operand), `git subtree add --prefix=DEST` (prefix operand),
`cp`/`mv` (all non-flag tokens). Path-based checks fire for any of these
targets. Shell globs in extracted paths (e.g. `.claude/settings*`) are matched conservatively:
if the pre-wildcard prefix is a prefix of a protected entry, the write is blocked.
Shell character-class globs (`[.json]`, `[sg]`) are also detected — `[` is included in the glob
character set alongside `*` and `?`.

The `protected_files` array in `guardrails.json` lets projects add arbitrary path-glob rules
with `deny`, `ask`, or `allow` decisions. Globs are case-insensitive (lowercased before regex
compile to match the case-insensitive comparison used on Windows). Brace expansion `{a,b}.json`
is supported. Non-object or null entries in the array are silently skipped. User-defined `ask`
rules under `.claude/` are automatically upgraded to `deny` in `checkProtectedFiles` because
Claude Code would otherwise silently auto-approve them.

All path rules and category rules participate in the same accumulator: most restrictive
decision wins, and multiple `ask`-level matches are shown together in a single confirmation
dialog.

## MCP tool coverage

The hook's wildcard matcher receives every tool call. `isWriteCapableTool()` recognizes:

Path extraction from MCP tool inputs covers: `file_path`, `path`, `target_path`, `notebook_path`, `filepath`, `output_path`, `out`, `file` (single-path keys); `destination`, `dst`, `target`, `to`, `new_path`, `link_target`, `dir`, `directory` (destination keys); `paths`, `files`, `targets` (array keys). The `file` key was added to cover MCP filesystem servers that use `{ file: path, content: ... }` shapes.

- Built-in: `Bash`, `Edit`, `Write`, `NotebookEdit`
- MCP tools whose name (after `mcp__`) contains any of: `write`, `edit`, `create`, `update`,
  `append`, `delete`, `remove`, `unlink`, `destroy`, `drop`, `clear`, `erase`, `wipe`, `purge`,
  `move`, `copy`, `patch`, `put`, `save`, `replace`, `truncate`, `rename`, `rewrite`, `insert`,
  `overwrite`, `upsert`, `set`, `upload`, `push`, `sync`, `commit`, `transfer`, `export`,
  `generate`, `store`, `dump`, `emit`, `persist`, `publish`, `apply`

`getTargetPaths()` extracts target file paths from common MCP shapes: `path`, `file_path`,
`target_path`, `notebook_path`, `filepath`, `output_path`, `out`, `destination`, `dst`, `target`,
`to`, `new_path`, `link_target`, `dir`, `directory`, `uri` (strips `file://` and authority
prefix including `file://localhost/`), array shapes (`paths`, `files`, `targets`) including
object-array shapes with `path`/`file_path`/`filePath`/`fileName`/`pathname`/`name` keys.

## Fail-safe two-mode behavior

The hook crashes are handled in two modes (set by the `inSecurityLogic` flag in
`pre-tool-use.js`):

- **Before init** (require errors, malformed stdin, unrecognized tool): fail **OPEN** (allow).
  An import-time bug cannot be attacker-influenced, and failing closed there has historically
  locked users out of every Claude Code session on the machine (incident 2026-06-21).
- **Inside security logic** (after stdin parsed and tool is recognized as write-capable): fail
  **CLOSED** (emit deny). A crash inside checkers may be triggered by attacker-controlled
  config and must not result in silent allow.

A regression test (`hooks-json-structure.js` and the manual import-failopen test) ensures the
fail-open path remains intact.

---

## What this plugin does NOT protect against

### Deliberately out of scope

**`curl-exec` (download-and-execute pipelines) - removed 2026-06-10.**

The original rule blocked `curl url | bash`, `curl url | node`, etc. on the assumption that
forcing the agent to use a two-step approach (`curl -o file && bash file`) would give a human
the opportunity to inspect the downloaded script before approving the second command.

In practice, agents do not inspect downloaded files before executing them. They simply issue
the two-step sequence automatically, making the rule a speed bump at best. The cost was real:
it generated consistent false positives on legitimate operations (e.g. piping API JSON responses
into a Node.js one-liner), and the error messages led agents into platform-specific path errors
(e.g. using `/tmp/` on Windows git-bash contexts where Node.js cannot resolve the path).

**The right mitigation for supply-chain / download risks is at the network layer** (egress
filtering, domain allowlists), not at the command string level.

### Delegation messages include `! <command>` - by design

Denial messages for categories like `rm`, `git-push`, `git-reset`, etc. include an explicit
`! <command>` that the user can run directly in Claude Code. A pentest review (2026-06-11)
flagged this as a potential social engineering vector: a prompt-injected agent could use the
template to craft a plausible justification and trick the user into running a dangerous command.

**This is an accepted risk, by design.** The rationale:

- The plugin's goal is to keep the user in the loop, not to create an impenetrable wall.
- Without the `! <command>`, the user has no easy path to approve a legitimate blocked action -
  they would have to know the Claude Code `!` syntax themselves.
- A determined prompt-injected agent can always invent the command; the template does not
  materially lower the bar for a sophisticated attacker.
- The explicit `! <command>` in the message is therefore a usability feature, not a security hole.

The real mitigation against prompt injection is upstream (content filtering, sandboxing),
not in the wording of denial messages.

### Known gaps (regex limitations)

The following are documented as known gaps in `tests/cases/bypass-vectors*.js`. They are not
fixed because fixing them would require a full shell parser or cause unacceptable false positives:

- Windows long-path prefix `\\?\` in Bash commands: normPath/normPathLiteral now strip it (BV-V7-07), but Write/Edit tool calls via MCP with this prefix are also handled.
- Variable-indirection for `rm` (`RM=/bin/rm $RM -rf /`) - BV-07
- Shell wrappers with non-bash/sh shells (`zsh -c "rm ..."`) - BV-NEW-01
- Interpreter one-liners calling filesystem APIs (`node -e "fs.rmSync(...)"`) - BV-NEW-02
- Inline env-var assignment without `export` (`LD_PRELOAD=... cmd`, `BASH_ENV=...`) - BV-NEW-03, BV-NEW-04
- Write/Edit tool targeting OS-critical paths (`/etc/passwd`, `C:\Windows\System32`) - BV-NEW-06, BV-NEW-07
- Shell quoting tricks that split the keyword (`ev''al`, `e\val`) - not detected by `/\beval\b/`
  because bash splice/escape is invisible to regex; these would error in most shells anyway
- `cmd /c "rm -rf foo"` on Windows — `"` is not in the rm separator set; `rm.exe` is not in
  Windows system PATH so the practical impact is near-zero (Git Bash environments use POSIX rm
  via shim, which IS caught at command-position)
- URL-safe base64 fingerprints — `buildBase64Fingerprints` uses standard alphabet (`+`/`/`).
  A hand-crafted URL-safe encoded secret would not be fingerprinted. Low exploitability:
  requires deliberate encoding choice by the agent.

### `agent-browser eval` exception assumes Claude Code execution context

The `eval` category allows `agent-browser eval` as a safe invocation of the Claude Code
agent-browser skill. This assumes:

- `agent-browser` is resolved by Claude Code as a skill, not via PATH lookup
- A PATH-injected binary named `agent-browser` could bypass this exception

This is an accepted risk: Claude Code skill invocation does not use PATH resolution, so a
malicious binary in PATH would not be invoked as `agent-browser eval` in normal operation.
If PATH is already compromised, the attacker has many more direct vectors available.

## Intentional design asymmetries

The following differences between rule types are deliberate and must not be "fixed":

### Bash-only rules

`categories`, `secrets-leak`, `secrets-not-gitignored`, and `secrets-file-access` only fire on
`Bash` tool calls. This is correct: these rules analyse command text, which `Edit`, `Write`,
and `NotebookEdit` do not have. There is nothing to match for non-Bash tools.

### Hard-deny rules with no config override

`secrets-not-gitignored` and `secrets-leak` always emit `deny` and cannot be overridden to
`ask` or `allow` via `guardrails.json`. This is intentional:

- **`secrets-not-gitignored`** — if the secrets file is not gitignored, every Bash command is a
  potential commit-time leak vector. There is no safe partial mode; the misconfiguration must be
  fixed before any command runs.
- **`secrets-leak`** — a command that contains a live secret value must never execute. There is
  no legitimate use case for an agent intentionally embedding a secret in a shell command.

Both rules participate in the unified accumulator (matches are collected, most restrictive wins)
but their `deny` decision cannot be softened by any configuration.

### Config override scope

All other rules accept `"deny"`, `"ask"`, or `"allow"` overrides in `guardrails.json`. The
intent is that project owners can consciously widen or narrow any non-security-critical rule.
The two hard-deny rules above are excluded from this scope because relaxing them would directly
undermine the plugin's primary security invariant.

---

## Configuration

Projects can override per-category decisions in `.claude/guardrails.json`:

```json
{
  "categories": {
    "git-push": "allow",
    "rm": "ask"
  }
}
```

Valid values: `"deny"` (block), `"ask"` (prompt user), `"allow"` (let through).
Unknown values fall back to the category's `defaultDecision`.
