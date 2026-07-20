# guardrails

Per-project guardrails for Claude Code. Intercepts every Bash command before execution and enforces configurable rules: block destructive commands by category, require user approval, or let them through. Also detects secret values leaking into commands and blocks them with a redirect message.

---

## How it works

The plugin registers a `PreToolUse` hook on `Bash`, `Edit`, `Write`, and `NotebookEdit`. Before any tool runs, the hook:

1. Reads `.claude/guardrails.json` from the project root (`cwd`). If absent, built-in category defaults still apply.
2. Runs **all** applicable checkers unconditionally - path-based rules (cross-home, guardrails-config, memory, secrets-file, protected_files) for every tool, plus category rules and secret checks for Bash.
3. Collects every match into a pool. Most restrictive decision wins (`deny` > `ask` > `allow`). Multiple `ask`-level matches are shown together in a single confirmation dialog.
4. Emits exactly one `permissionDecision` (`deny`, `ask`, or `allow`) covering all triggered rules.
5. Verifies that the secrets file is listed in `.gitignore` - if not, **all Bash commands are blocked** until fixed (this is a hard `deny` that dominates all other matches).

Logs are written to `.claude/logs/guardrails/guardrails-YYYY-MM-DD.log` inside the project. Secret values are never logged; only key names are.

---

## Installation

The plugin is installed at:
```
~/.claude/plugins/local-marketplace/plugins/guardrails/
```

It is picked up automatically by Claude Code via the local marketplace. No `npm install` required - it uses Node.js stdlib only.

---

## Project setup

### 1. Create `.claude/guardrails.json`

Copy `guardrails.example.json` from the plugin directory and adjust to your needs:

```json
{
  "categories": {
    "git-stash":          "deny",
    "git-reset":          "ask",
    "git-push":           "ask",
    "git-commit":         "allow",
    "git-clean":          "deny",
    "git-branch-delete":  "deny",
    "rm":                 "ask",
    "kill":               "allow",
    "chmod":              "allow",
    "docker-rm":          "deny",
    "drop-db":            "deny",
    "format-disk":        "deny"
  },
  "secrets": {
    "file": ".claude/guardrails.secrets",
    "redirect_message": "Do not use raw credentials. Use the project CLI tooling instead (e.g. `jira`, `gh`, `aws sso`)."
  }
}
```

The `categories` block is optional. The `secrets` block is optional. Omit either if not needed.

### 2. Create `.claude/guardrails.secrets` (optional)

One `KEY=VALUE` per line. Empty lines and `#` comments are ignored. `export KEY=VALUE` and quoted values are also accepted.

```
# Jira
JIRA_API_TOKEN=xoxb-abc123

# GitHub
GITHUB_TOKEN=ghp_xxxxx

# Link an existing .env file (relative to project root)
@.env

# Link a .properties file (format auto-detected from extension)
@config/app.properties

# Absolute path
@C:/Secrets/shared.env

# Explicit format override (for files with non-standard extensions)
@infra/secrets.txt [properties]
```

Linked files are loaded on top of the main secrets. Format is auto-detected from the file extension:
- `.properties` → Java properties parser (`KEY = VALUE`, `KEY: VALUE`, `!` and `#` comments)
- everything else → env parser (`KEY=VALUE`, `export KEY=VALUE`, quoted values, inline `# comments`)

Each file loaded emits an info log line: `Secrets loaded | file=... format=... count=N`.

### 3. Add the secrets file to `.gitignore`

```
.claude/guardrails.secrets
```

**If this is missing, the plugin will block every Bash command** and tell Claude to fix it first.

---

## Decision values

| Value | Effect |
|-------|--------|
| `deny` | Command is blocked. Claude sees an explanation and must find another approach. |
| `ask` | Claude Code surfaces a permission dialog to the user before proceeding. |
| `allow` | No restriction. Equivalent to not listing the category at all. |

If a category is not listed in `guardrails.json`, its built-in default decision applies (see the Supported categories table). To explicitly allow a category, set it to `"allow"`.

---

## Supported categories

| Category | What it catches |
|---|---|
| `git-stash` | `git stash` (any subcommand) |
| `git-reset` | `git reset` |
| `git-push` | `git push` |
| `git-commit` | `git commit` |
| `git-clean` | `git clean` |
| `git-branch-delete` | `git branch -d/-D` and `git push --delete` |
| `rm` | Any `rm` invocation |
| `kill` | `kill`, `killall`, `pkill`, `taskkill` |
| `chmod` | `chmod` and `chown` |
| `docker-rm` | `docker rm/rmi` and `docker *prune` |
| `drop-db` | `DROP TABLE/DATABASE/SCHEMA`, `TRUNCATE TABLE` |
| `format-disk` | `mkfs`, `format`, `dd if=` |
| `git-push-force` | `git push --force` / `git push -f` |
| `git-restore` | `git restore` (discards working-tree changes) |
| `git-revert` | `git revert` |
| `eval` | `eval`, `exec $...`, `source /tmp/`, `. /tmp/` |
| `cron-at` | `crontab -`, `at`, `echo ... cron`, `/etc/cron.*`, `/var/spool/cron/` |
| `systemctl-stop` | `systemctl stop/disable/mask/kill`, `service ... stop` |
| `firewall` | `iptables -F`, `nft flush`, `ufw disable`, `netsh advfirewall ... off` |
| `log-clear` | Truncate or remove `/var/log/` files, `Clear-EventLog`, `wevtutil cl` |
| `sudo-shell` | `sudo bash/sh/zsh`, `sudo -s`, `sudo -i`, `sudo vim/less/awk/perl/python` |
| `env-hijack` | `export LD_PRELOAD=`, `LD_LIBRARY_PATH=`, `PATH=.../tmp`, `DYLD_INSERT_LIBRARIES=` |
| `python` | `python`, `python3`, `pip`, `conda`, `poetry`, `virtualenv`, `pyenv`, `pytest`, `uv pip/run/...` |
| `ln` | `ln`, `ln -s`, `ln --symbolic`, `mklink` (Windows), `New-Item -ItemType SymbolicLink/HardLink/Junction` (PowerShell). Default `deny` because symlinks can be used to bypass path-prefix checks. |

### Protected files

The `protected_files` array lets you protect arbitrary paths by glob pattern, independent of the command category:

```json
{
  "protected_files": [
    { "glob": "**/*.pem",      "decision": "deny" },
    { "glob": "**/*.key",      "decision": "deny" },
    { "glob": ".env*",         "decision": "ask"  },
    { "glob": "src/config/**", "decision": "ask"  }
  ]
}
```

Patterns are relative to the project root and use the following glob semantics:

| Token | Matches |
|-------|---------|
| `**`  | Any sequence of characters including `/` (crosses directory boundaries) |
| `*`   | Any sequence of characters except `/` (single directory segment) |
| `?`   | Any single character except `/` |

**Precedence when multiple rules match:** the most restrictive decision wins (`deny` > `ask` > `allow`).

The check applies to all write tools (`Edit`, `Write`, `NotebookEdit`) and to write paths extracted from `Bash` commands (redirections, `tee`, `cp`, `mv`, `curl -o`, `wget -O`, `rm`/`rmdir`). `rm` targets are included, so a `deny` rule also protects against deletion - on top of the `rm` category. Paths outside the project root are not evaluated against these rules.

---

### Path-based categories

These categories enforce path-level policies and can be overridden in `guardrails.json` like any other category:

| Category | What it catches | Default |
|---|---|---|
| `cross-home-write` | Any Edit/Write/Bash that targets a path outside the project dir but inside `$HOME/.claude` | `deny` |
| `guardrails-config-write` | Edit/Write/Bash targeting `.claude/guardrails.json` | `deny` |
| `fleet-config-write` | Edit/Write/Bash targeting `.claude/w-fleet.json` | `deny` |
| `settings-write` | Edit/Write/Bash targeting `.claude/settings.json`, `.claude/settings.local.json`, `.claude/CLAUDE.md`, `.claude/hooks/**`, `.claude/skills/**` | `deny` |
| `memory-write` | Edit/Write/Bash targeting `.claude/memory/` files | `deny` |
| `secrets-file-write` | Edit/Write/Bash targeting the configured secrets file | `deny` |
| `secrets-file-access` | Bash commands that reference a protected secrets file (cat, source, grep, etc.) | `deny` |

To allow a project legitimately located inside `$HOME/.claude`, add `"cross-home-write": "allow"` to its `guardrails.json`.

---

## Logs

Logs are stored per project at:
```
$PROJECT/.claude/logs/guardrails/guardrails-YYYY-MM-DD.log
```

Format matches `command-log`::
```
[2026-05-29 09:30:27] [abc12345:M] [ INFO] Category match: git-stash → deny | cmd=git stash list
[2026-05-29 09:30:27] [abc12345:M] [ WARN] Secret leak detected: key=JIRA_API_TOKEN | cmd=<redacted>
```

Retention: 30 days, max 100 files. Pruning runs automatically on each log write.

---

## Notes for agents

- The hook runs on **every Bash tool call**, before execution.
- If `guardrails.json` is absent, built-in category defaults still apply. To fully disable guardrails for a project, create an empty `{}` config and set each category to `"allow"`.
- `deny` is always final; it cannot be overridden by other hooks.
- When `ask` is returned, Claude Code pauses and prompts the user; the agent resumes after the user decides.
- `skipDangerousModePermissionPrompt: true` in settings.json has **no effect** on `ask` decisions from this hook. It only suppresses the one-time confirmation dialog when activating `bypassPermissions` mode. Do not cite it when investigating missing ask prompts.

### Claude Code silently ignores `ask` for paths under `.claude/`

**Critical security caveat.** Claude Code does **not** emit a `PermissionRequest` event for Write/Edit tool calls targeting any file under the project's `.claude/` directory. The hook's `permissionDecision: "ask"` is silently auto-approved - no dialog, no prompt, no `PermissionRequest` hook fired. This was empirically validated on 2026-06-21 with 7 controlled tests across `.claude/memory/`, `.claude/docs/`, and `.claude/random/` subdirectories. The same `ask` on paths outside `.claude/` (e.g. `tmp/`, project root) correctly prompts.

`deny` and `allow` decisions ARE respected for `.claude/` paths. Only `ask` is broken in this scope.

**Consequence:** rules that protect `.claude/`-scoped writes (`memory-write`, `guardrails-config-write`, `fleet-config-write`, `secrets-file-write`, and any `protected_files` glob targeting `.claude/`) **must default to `deny`** - `ask` provides no protection. To allow ad-hoc writes, the user must explicitly set the rule to `allow` in `guardrails.json`.
- Secret values are matched as **literal substrings** and as **base64 fingerprints** (all byte-alignment offsets). Values are never written to logs - only key names appear.
- Linked secret files (`@path`) support `env` and `properties` formats, auto-detected by extension or overridden with `[tag]`.
- The `.gitignore` check walks up to the git root if the project dir itself has no `.git`.
- All errors are caught silently - the hook never crashes a tool call.
