'use strict';

const fs   = require('fs');
const path = require('path');

function safeRealpath(p) {
  try {
    return fs.realpathSync(p);
  } catch (_) {
    const parent = path.dirname(p);
    if (parent === p) return p;
    try {
      return path.join(fs.realpathSync(parent), path.basename(p));
    } catch (_) {
      return p;
    }
  }
}

function expandTilde(p) {
  const home = (process.env.USERPROFILE || process.env.HOME || '').replace(/\\/g, '/');
  // Expand ${HOME} and ${USERPROFILE} (curly-brace forms used in double-quoted strings).
  p = p.replace(/\$\{(?:HOME|USERPROFILE)\}/g, home);
  // Expand $HOME and $USERPROFILE (bare variable forms).
  p = p.replace(/\$(?:HOME|USERPROFILE)(?=[/\\]|$)/g, home);
  if (p !== '~' && !p.startsWith('~/') && !p.startsWith('~\\')) return p;
  return home + '/' + p.slice(2);
}

// Converts git-bash style paths (/c/foo) to Windows paths (C:/foo) on Windows.
function fromGitBash(p) {
  if (process.platform !== 'win32') return p;
  const m = p.match(/^\/([a-zA-Z])(\/.*)?$/);
  if (m) return m[1].toUpperCase() + ':' + (m[2] || '/');
  return p;
}

// Strips the Windows extended-path prefix `\\?\` (and `\\?\UNC\` → `//`).
// Without this, path.resolve may preserve the prefix, causing startsWith
// comparisons against normalised paths to fail silently (BV-V7-07).
function stripExtendedPrefix(p) {
  if (typeof p !== 'string') return p;
  // \\?\UNC\server\share\... → //server/share/...
  if (/^\\\\\?\\UNC\\/i.test(p)) return p.slice(7).replace(/\\/g, '/');
  // \\?\C:\... → C:\...
  if (/^\\\\\?\\/.test(p)) return p.slice(4);
  return p;
}

// Normalises for case-insensitive comparison (needed on Windows).
// cwd must be event.cwd, not process.cwd().
function normPath(p, cwd) {
  const normalised = expandTilde(fromGitBash(stripExtendedPrefix(p)));
  const resolved = cwd ? path.resolve(cwd, normalised) : path.resolve(normalised);
  return safeRealpath(resolved).toLowerCase().replace(/\\/g, '/');
}

// Like normPath but does NOT follow symlinks. Used as a second comparison axis
// when checking .claude/-scoped writes: if the literal path is under .claude/
// we must deny even if realpath resolves outside (symlink attack - see
// symlink-defense.js). The attacker would otherwise plant a symlink inside
// .claude/ pointing outside, then write through it to bypass the prefix check.
function normPathLiteral(p, cwd) {
  const normalised = expandTilde(fromGitBash(stripExtendedPrefix(p)));
  const resolved = cwd ? path.resolve(cwd, normalised) : path.resolve(normalised);
  return resolved.toLowerCase().replace(/\\/g, '/');
}

function isDescendantOf(child, ancestor) {
  const c = normPath(child);
  const a = normPath(ancestor);
  return c === a || c.startsWith(a + '/');
}

// Extracts absolute literal write-target paths from a Bash command.
// Best-effort: covers redirections, tee, cp/mv, curl, wget, rm/rmdir.
function extractBashWritePaths(command, projectDir) {
  const candidates = [];
  const push = (m) => { if (m) candidates.push(m); };

  // Bash allows redirects without whitespace: `echo x>file`, `cat<<<EOF>>f`.
  // Match the operator then optional whitespace before the path.
  for (const m of command.matchAll(/>>?\s*([^\s|&;'"<>]+)/g)) push(m[1]);
  for (const m of command.matchAll(/>>?\s*"([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/>>?\s*'([^']+)'/g)) push(m[1]);

  for (const m of command.matchAll(/\btee(?:\s+(?:-a|--append))*\s+((?:[^\s|&;'"]+\s*)+)/g)) {
    // Strip trailing shell metacharacters that cannot be part of a bare path token:
    // `> >(tee file)` captures "file)" - the closing paren must be dropped.
    for (const p of m[1].trim().split(/\s+/)) push(p.replace(/[)>}]+$/, ''));
  }
  for (const m of command.matchAll(/\btee(?:\s+(?:-a|--append))*\s+"([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/\btee(?:\s+(?:-a|--append))*\s+'([^']+)'/g)) push(m[1]);

  // sponge FILE (moreutils): reads all stdin then atomically writes to FILE.
  // Same extraction pattern as tee, including -a/--append flag skip and trailing ) strip.
  for (const m of command.matchAll(/\bsponge(?:\s+(?:-a|--append))*\s+((?:[^\s|&;'"]+\s*)+)/g)) {
    for (const p of m[1].trim().split(/\s+/)) push(p.replace(/[)>}]+$/, ''));
  }
  for (const m of command.matchAll(/\bsponge(?:\s+(?:-a|--append))*\s+"([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/\bsponge(?:\s+(?:-a|--append))*\s+'([^']+)'/g)) push(m[1]);

  // rsync src dst - last non-flag, non-option-value token is the destination.
  // rsync -av src dst, rsync --checksum src dst, rsync -r src/ dst/ - same heuristic.
  // Also extract --backup-dir=DIR (directory where backup copies are written).
  for (const m of command.matchAll(/\brsync\b([^|&;]*)/g)) {
    const rawTokens = [...m[1].matchAll(/"([^"]+)"|'([^']+)'|([^\s|&;'"]+)/g)]
      .map(t => t[1] ?? t[2] ?? t[3]);
    const nonFlags = rawTokens.filter(t => t && !t.startsWith('-'));
    if (nonFlags.length >= 2) push(nonFlags[nonFlags.length - 1]);
    // Extract --backup-dir=VALUE or --backup-dir VALUE (writes backup copies to a separate dir).
    for (let i = 0; i < rawTokens.length; i++) {
      const t = rawTokens[i];
      if (!t) continue;
      if (t.startsWith('--backup-dir=')) {
        push(t.slice('--backup-dir='.length));
      } else if (t === '--backup-dir' && i + 1 < rawTokens.length) {
        push(rawTokens[++i]);
      }
    }
  }

  // git clone URL [DEST] - the optional second non-flag arg is the destination directory.
  // git submodule add URL DEST - last non-flag is the destination path.
  // git subtree add --prefix=DEST URL REF - extract --prefix= value.
  for (const m of command.matchAll(/\bgit\b[^|&;]*\bclone\b([^|&;]*)/g)) {
    const tokens = [...m[1].matchAll(/"([^"]+)"|'([^']+)'|([^\s|&;'"]+)/g)]
      .map(t => t[1] ?? t[2] ?? t[3])
      .filter(t => t && !t.startsWith('-'));
    if (tokens.length >= 2) push(tokens[tokens.length - 1]);
  }
  for (const m of command.matchAll(/\bgit\b[^|&;]*\bsubmodule\s+add\b([^|&;]*)/g)) {
    const tokens = [...m[1].matchAll(/"([^"]+)"|'([^']+)'|([^\s|&;'"]+)/g)]
      .map(t => t[1] ?? t[2] ?? t[3])
      .filter(t => t && !t.startsWith('-'));
    if (tokens.length >= 2) push(tokens[tokens.length - 1]);
  }
  for (const m of command.matchAll(/\bgit\b[^|&;]*\bsubtree\s+add\b[^|&;]*--prefix=([^\s|&;'"]+)/g)) {
    push(m[1]);
  }

  // cp/mv: extract ALL non-flag tokens and push the last one (the destination).
  // A single regex captures only src2 in multi-source form (cp src1 src2 dst).
  // Fix: tokenise the full argument segment and push every non-flag token so that
  // both two-arg (src dst) and multi-source (src1 src2 ... dst) are covered.
  for (const m of command.matchAll(/\b(?:cp|mv)\b([^|&;]*)/g)) {
    const tokens = [...m[1].matchAll(/"([^"]+)"|'([^']+)'|([^\s|&;'"]+)/g)]
      .map(t => t[1] ?? t[2] ?? t[3])
      .filter(t => t && !t.startsWith('-'));
    // Push all non-flag tokens: for two-arg form this is [src, dst];
    // for multi-source it is [src1, src2, ..., dst]. All become candidates -
    // path-based checkers normalise and compare, so false src entries are harmless.
    for (const t of tokens) push(t);
  }

  for (const m of command.matchAll(/\bcurl\b[^|&;]*?\s(?:-o|--output)[= ]([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\bcurl\b[^|&;]*?\s(?:-o|--output)[= ]"([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/\bcurl\b[^|&;]*?\s(?:-o|--output)[= ]'([^']+)'/g)) push(m[1]);
  // curl -oFILE (concatenated, no separator) - valid curl syntax.
  for (const m of command.matchAll(/\bcurl\b[^|&;]*?\s-o([^-\s][^\s|&;'"]*)/g)) push(m[1]);
  // curl --output-dir DIR (curl 7.73+) - sets download directory for all outputs.
  for (const m of command.matchAll(/\bcurl\b[^|&;]*?\s--output-dir[= ]([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\bcurl\b[^|&;]*?\s--output-dir[= ]"([^"]+)"/g)) push(m[1]);

  for (const m of command.matchAll(/\bwget\b[^|&;]*?\s(?:-O|--output-document)[= ]([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\bwget\b[^|&;]*?\s(?:-O|--output-document)[= ]"([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/\bwget\b[^|&;]*?\s(?:-O|--output-document)[= ]'([^']+)'/g)) push(m[1]);
  // wget -OFILE (concatenated, no separator) - valid wget syntax.
  for (const m of command.matchAll(/\bwget\b[^|&;]*?\s-O([^-\s][^\s|&;'"]*)/g)) push(m[1]);
  // wget -P DIR / --directory-prefix=DIR / --directory-prefix DIR (sets download directory).
  for (const m of command.matchAll(/\bwget\b[^|&;]*?\s-P\s+([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\bwget\b[^|&;]*?\s--directory-prefix[= ]([^\s|&;'"]+)/g)) push(m[1]);

  // rm/rmdir - enables path-based checks on deletions too
  for (const m of command.matchAll(/\brm(?:dir)?\b([^|&;]*)/g)) {
    for (const tok of m[1].matchAll(/"([^"]+)"|'([^']+)'|([^\s|&;'"]+)/g)) {
      const p = tok[1] ?? tok[2] ?? tok[3];
      if (p && !p.startsWith('-')) push(p);
    }
  }
  // Windows deletion: del / erase, Remove-Item, ri (PowerShell alias),
  // rmdir-like rd /s. Same command-position requirement as rm to avoid false
  // positives - `ri` would otherwise match Unix flag bundles like `grep -ri`.
  // The lookahead-style anchor: start of string OR after a shell separator.
  const winDelRe = /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:del|erase|Remove-Item|ri|rd)\b([^|&;]*)/g;
  // case-insensitive variant for Remove-Item / Erase / RD
  const winDelReI = /(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:Del|Erase|RD)\b([^|&;]*)/gi;
  const handle = (m) => {
    for (const tok of m[1].matchAll(/"([^"]+)"|'([^']+)'|([^\s|&;'"]+)/g)) {
      const p = tok[1] ?? tok[2] ?? tok[3];
      if (!p) continue;
      // Filter PowerShell-style flags (-Recurse, -Force, -Path, -LiteralPath)
      // and cmd-style switches (/s, /q, /f, /a).
      if (p.startsWith('-')) continue;
      if (/^\/[a-zA-Z]$/.test(p)) continue;
      push(p);
    }
  };
  for (const m of command.matchAll(winDelRe)) handle(m);
  for (const m of command.matchAll(winDelReI)) handle(m);

  // sed -i / sed --in-place - extract file arguments.
  // Forms:
  //   sed -i SCRIPT FILE [FILE...]                 (script as first non-flag)
  //   sed -i -e SCRIPT [-e SCRIPT...] FILE...     (scripts via -e, files at end)
  //   sed -i -f SCRIPTFILE FILE...                (script in file, files at end)
  //   sed -i.bak / --in-place=.bak                 (backup-suffix variant)
  //
  // Skip flags and consume args after -e/-f. After that:
  //   - if any -e or -f was seen, ALL remaining non-flag tokens are files
  //   - otherwise, the FIRST non-flag is the script and the rest are files
  for (const m of command.matchAll(/\bsed\b([^|&;]*)/g)) {
    const segment = m[1];
    if (!/(?:^|\s)(?:-\w*i(?:\.\S+)?|--in-place(?:=\S+)?)\b/.test(segment)) continue;
    const tokens = [...segment.matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)].map(t => t[1] ?? t[2] ?? t[3]);
    const nonFlags = [];
    let skip = false;
    let scriptViaFlag = false;
    for (const tok of tokens) {
      if (skip) { skip = false; continue; }
      if (tok.startsWith('-')) {
        if (tok === '-e' || tok === '-f') { skip = true; scriptViaFlag = true; }
        continue;
      }
      nonFlags.push(tok);
    }
    const fileArgs = scriptViaFlag ? nonFlags : nonFlags.slice(1);
    for (const f of fileArgs) push(f);
  }

  // perl -i / perl -pi / perl -ni - in-place edit. Files come after the script.
  for (const m of command.matchAll(/\bperl\b([^|&;]*)/g)) {
    const segment = m[1];
    if (!/(?:^|\s)-\w*i/.test(segment)) continue;
    const tokens = [...segment.matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)].map(t => t[1] ?? t[2] ?? t[3]);
    let skip = false;
    const nonFlags = [];
    for (const tok of tokens) {
      if (skip) { skip = false; continue; }
      if (tok.startsWith('-')) { if (tok === '-e' || tok === '-M') skip = true; continue; }
      nonFlags.push(tok);
    }
    // First non-flag is the script (when -e was inline) or first file. Heuristic:
    // tokens that look like a substitute command (s/.../.../) are scripts.
    for (const f of nonFlags) {
      if (/^s[\/!|].*[\/!|]/.test(f)) continue; // sed-style script
      push(f);
    }
  }

  // openssl ... -out FILE  /  gpg ... --output FILE
  for (const m of command.matchAll(/\b(?:openssl|gpg)\b[^|&;]*?\s(?:-out|-o|--output)[= ]([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\b(?:openssl|gpg)\b[^|&;]*?\s(?:-out|-o|--output)[= ]"([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/\b(?:openssl|gpg)\b[^|&;]*?\s(?:-out|-o|--output)[= ]'([^']+)'/g)) push(m[1]);

  // dd if=... of=FILE
  for (const m of command.matchAll(/\bdd\b[^|&;]*?\bof=([^\s|&;'"]+)/g)) push(m[1]);

  // tar -C DEST / tar --directory=DEST / tar --directory DEST  (extraction destination)
  for (const m of command.matchAll(/\btar\b[^|&;]*?\s-C\s+([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\btar\b[^|&;]*?\s-C\s+"([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/\btar\b[^|&;]*?\s--directory=([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\btar\b[^|&;]*?\s--directory="([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/\btar\b[^|&;]*?\s--directory\s+([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\btar\b[^|&;]*?\s--directory\s+"([^"]+)"/g)) push(m[1]);
  // tar --one-top-level=DEST / --one-top-level DEST (GNU tar 1.28+)
  for (const m of command.matchAll(/\btar\b[^|&;]*?\s--one-top-level=([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\btar\b[^|&;]*?\s--one-top-level\s+([^\s|&;'"]+)/g)) push(m[1]);

  // unzip ... -d DEST
  for (const m of command.matchAll(/\bunzip\b[^|&;]*?\s-d\s+([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\bunzip\b[^|&;]*?\s-d\s+"([^"]+)"/g)) push(m[1]);

  // install [-m MODE] [-o user] [-g group] [-t DIR] SRC [SRC...] / install SRC DEST
  // -t DIR (--target-directory=DIR): all non-flag args are sources; DIR is the destination.
  // Without -t: last non-flag is destination.
  for (const m of command.matchAll(/\binstall\b([^|&;]*)/g)) {
    const segment = m[1];
    const tokens = [...segment.matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)].map(t => t[1] ?? t[2] ?? t[3]);
    let targetDir = null;
    const nonFlags = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      if (tok.startsWith('--target-directory=')) { targetDir = tok.slice('--target-directory='.length); continue; }
      if (tok.startsWith('-')) {
        if (/^-(m|o|g)$/.test(tok)) { i++; continue; }
        if (tok === '-t' || tok === '--target-directory') { if (i + 1 < tokens.length) { targetDir = tokens[++i]; } continue; }
        continue;
      }
      nonFlags.push(tok);
    }
    if (targetDir) {
      push(targetDir);
    } else if (nonFlags.length >= 2) {
      push(nonFlags[nonFlags.length - 1]);
    }
  }

  // patch -o FILE / patch --output=FILE - writes patched result to a new file.
  for (const m of command.matchAll(/\bpatch\b[^|&;]*?\s(?:-o|--output)[= ]([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\bpatch\b[^|&;]*?\s(?:-o|--output)[= ]"([^"]+)"/g)) push(m[1]);
  for (const m of command.matchAll(/\bpatch\b[^|&;]*?\s(?:-o|--output)[= ]'([^']+)'/g)) push(m[1]);

  // ssh-keygen -f FILE  (writes private + public key files)
  for (const m of command.matchAll(/\bssh-keygen\b[^|&;]*?\s-f\s+([^\s|&;'"]+)/g)) push(m[1]);
  for (const m of command.matchAll(/\bssh-keygen\b[^|&;]*?\s-f\s+"([^"]+)"/g)) push(m[1]);

  // awk / gawk / mawk -i inplace 'script' FILE - GNU awk 4.1+ in-place mode.
  // The token "inplace" is the value of -i, then a script, then file(s).
  for (const m of command.matchAll(/\b(?:gawk|mawk|nawk|awk)\b([^|&;]*)/g)) {
    const segment = m[1];
    if (!/\s-i\s+inplace\b/.test(segment)) continue;
    const tokens = [...segment.matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)].map(t => t[1] ?? t[2] ?? t[3]);
    // Collect all non-flag tokens, tracking whether -f provided an external script
    // and whether -i inplace was seen. After the loop:
    //   - If -f: ALL non-flags collected after -i inplace are targets.
    //   - Otherwise: one non-flag is the inline script (could be before OR after -i inplace);
    //     the rest are targets.
    // Two-pass: first collect state, then decide which non-flags are targets.
    let inplaceIdx = -1; // position in tokens[] of the "-i" token
    let scriptViaF = false;
    {
      let si = false;
      for (let i = 0; i < tokens.length; i++) {
        if (si) { si = false; continue; }
        if (tokens[i] === '-i') { si = true; inplaceIdx = i; }
        else if (tokens[i] === '-f') { si = true; scriptViaF = true; }
      }
    }
    if (inplaceIdx === -1) continue; // no -i inplace found
    // Collect non-flag tokens in order, noting which side of -i they're on.
    const preNonFlags = [];
    const postNonFlags = [];
    {
      let si = false;
      let pastInplace = false;
      for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i];
        if (si) { si = false; continue; }
        if (tok === '-i') { si = true; pastInplace = true; continue; }
        if (tok === '-f') { si = true; continue; }
        if (tok.startsWith('-')) continue;
        if (pastInplace) postNonFlags.push(tok);
        else preNonFlags.push(tok);
      }
    }
    if (scriptViaF) {
      // External script via -f: ALL non-flags (pre and post) are targets.
      for (const t of [...preNonFlags, ...postNonFlags]) push(t);
    } else {
      // Inline script: one non-flag is the script token. It's either the FIRST pre-inplace
      // non-flag (script before -i), or the FIRST post-inplace non-flag (script after -i).
      // Exception: if there is exactly ONE non-flag total, awk is reading its program from
      // stdin - the single token is a target file, not an inline script.
      const all = [...preNonFlags, ...postNonFlags];
      if (all.length === 1) {
        push(all[0]); // stdin-as-script: lone token is the file
      } else {
        for (const t of all.slice(1)) push(t); // skip first non-flag (inline script)
      }
    }
  }

  // yq -i 'expr' FILE - YAML in-place edit (mikefarah/yq).
  for (const m of command.matchAll(/\byq\b([^|&;]*)/g)) {
    const segment = m[1];
    if (!/(?:^|\s)-i(?:\b|\s)/.test(segment)) continue;
    const tokens = [...segment.matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)].map(t => t[1] ?? t[2] ?? t[3]);
    const nonFlags = tokens.filter(t => !t.startsWith('-'));
    // First non-flag is the expression, rest are file(s).
    for (const f of nonFlags.slice(1)) push(f);
  }

  // unlink FILE - POSIX single-file deletion (no flags). Same command-position anchor as rm.
  for (const m of command.matchAll(/(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:sudo\s+)?unlink\b([^|&;]*)/g)) {
    const tokens = [...m[1].matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)].map(t => t[1] ?? t[2] ?? t[3]);
    for (const tok of tokens) {
      if (tok && !tok.startsWith('-')) push(tok);
    }
  }

  // shred [-u] [-z] [options] FILE... - secure overwrite/delete. Same command-position
  // anchor as rm to avoid false positives. Extract file operands (skip flags).
  for (const m of command.matchAll(/(?:^|&&|\|\||\||;|`|\$\(|[\n\r({])\s*(?:sudo\s+)?shred\b([^|&;]*)/g)) {
    const tokens = [...m[1].matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)].map(t => t[1] ?? t[2] ?? t[3]);
    for (const tok of tokens) {
      if (!tok.startsWith('-')) push(tok);
    }
  }

  // truncate -s N FILE / truncate --size=N FILE - truncates file to given size.
  // Dangerous when N=0 (zeroes the file). Extract the file operand.
  for (const m of command.matchAll(/\btruncate\b([^|&;]*)/g)) {
    const segment = m[1];
    if (!/(?:\s|^)(?:-s\b|--size(?:=|\s))/.test(segment)) continue;
    const tokens = [...segment.matchAll(/"([^"]+)"|'([^']+)'|(\S+)/g)].map(t => t[1] ?? t[2] ?? t[3]);
    let skipNext = false;
    for (const tok of tokens) {
      if (skipNext) { skipNext = false; continue; }
      if (tok === '-s' || tok === '--size') { skipNext = true; continue; }
      if (tok.startsWith('--size=')) continue;
      if (tok.startsWith('-')) continue;
      push(tok);
    }
  }

  return candidates
    .map(expandTilde)
    .map(fromGitBash)
    .map((p) => path.isAbsolute(p.replace(/\//g, path.sep)) ? p : path.join(projectDir, p))
    .filter((p) => path.isAbsolute(p));
}

// Best-effort extraction of all target file paths from a tool_input.
// Returns an array (possibly empty) so callers can iterate uniformly.
// Built-in tools (Edit/Write/NotebookEdit) have known shapes; MCP tools use
// a variety of shapes - single (path/file_path/target_path), pair-style
// (src+dst, source+destination), or array (paths/files).
function getTargetPaths(event) {
  const ti = event?.tool_input ?? {};
  switch (event.tool_name) {
    case 'Edit':
    case 'Write':
      return ti.file_path ? [ti.file_path] : [];
    case 'NotebookEdit':
      return ti.notebook_path ? [ti.notebook_path] : [];
  }
  const out = [];
  // URI form: file:///path/to/file or file://authority/path/to/file
  // (LSP-style and some filesystem MCP servers).
  if (typeof ti.uri === 'string' && /^file:\/\//.test(ti.uri)) {
    // Strip the file:// scheme AND any authority component (e.g. "localhost").
    // After this, p starts with the path portion (with or without leading /).
    let p = ti.uri.replace(/^file:\/\/[^/]*/, '');
    // file:///C:/foo on Windows → strip leading slash before drive letter
    if (/^\/[a-zA-Z]:/.test(p)) p = p.slice(1);
    try { out.push(decodeURIComponent(p)); } catch (_) { out.push(p); }
  }
  // Single-path keys
  for (const k of ['file_path', 'path', 'target_path', 'notebook_path', 'filepath', 'output_path', 'out', 'file']) {
    if (typeof ti[k] === 'string' && ti[k]) out.push(ti[k]);
  }
  // Destination-side of pair-style inputs (the source is read-only, destination is the WRITE)
  for (const k of ['destination', 'dst', 'target', 'to', 'new_path', 'link_target', 'dir', 'directory']) {
    if (typeof ti[k] === 'string' && ti[k]) out.push(ti[k]);
  }
  // Array shapes - accept both strings and {path,...}/{file_path,...} objects.
  for (const k of ['paths', 'files', 'targets']) {
    if (!Array.isArray(ti[k])) continue;
    for (const elem of ti[k]) {
      if (typeof elem === 'string' && elem) out.push(elem);
      else if (elem && typeof elem === 'object') {
        // Cover both snake_case and camelCase conventions used across MCP servers.
        for (const subKey of ['path', 'file_path', 'filePath', 'filepath', 'fileName', 'pathname', 'name']) {
          if (typeof elem[subKey] === 'string' && elem[subKey]) { out.push(elem[subKey]); break; }
        }
      }
    }
  }
  return out;
}

// Back-compat: scalar form returning the first path, or null.
function getTargetPath(event) {
  const arr = getTargetPaths(event);
  return arr.length > 0 ? arr[0] : null;
}

// Returns true if the tool name represents a write-capable operation that
// should be screened by path-based checks. Includes built-in write tools
// AND MCP tools whose name suggests a write operation. The wildcard hook
// matcher feeds every tool through here; non-write tools are skipped early.
function isWriteCapableTool(toolName) {
  if (!toolName) return false;
  if (toolName === 'Bash' || toolName === 'Edit' || toolName === 'Write' || toolName === 'NotebookEdit') return true;
  if (!toolName.startsWith('mcp__')) return false;
  // Verbs covering all destructive/mutating operations seen across MCP servers.
  // 'run'/'exec' are intentionally omitted to avoid screening read-only tools
  // named e.g. mcp__shell__exec_query - can be added if a specific server needs it.
  return /(?:^|_)(?:write|edit|create|update|append|delete|remove|unlink|destroy|drop|clear|erase|wipe|purge|move|copy|patch|put|save|replace|truncate|rename|rewrite|insert|overwrite|upsert|set|upload|push|sync|commit|transfer|export|generate|store|dump|emit|persist|publish|apply)(?:_|$)/i.test(toolName);
}

// Returns paths of the main secrets file + all @ linked files.
function collectProtectedSecretPaths(projectDir, config) {
  const secretsFile = config?.secrets?.file;
  if (!secretsFile) return [];
  const secretsFilePath = path.isAbsolute(secretsFile)
    ? secretsFile
    : path.join(projectDir, secretsFile);
  const paths = [secretsFilePath];
  try {
    // Apply the same FIFO/oversize guard as loadSecrets to avoid hanging the hook.
    let st;
    try { st = fs.statSync(secretsFilePath); } catch (_) { return paths; }
    if (!st.isFile() || st.size > 10 * 1024 * 1024) return paths;
    const content = fs.readFileSync(secretsFilePath, 'utf8');
    const projectAbs = path.resolve(projectDir);
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('@')) continue;
      const linkPath = trimmed.slice(1).replace(/\s+\[\w+\]$/, '').trim();
      if (!linkPath) continue;
      const resolved = path.isAbsolute(linkPath) ? linkPath : path.join(projectDir, linkPath);
      // Mirror loadSecrets: skip relative links that resolve outside projectDir
      // (../ traversal). Without this, a malicious secrets file with `@../../etc/passwd`
      // would make checkSecretsFileAccess deny any command mentioning "passwd".
      if (!path.isAbsolute(linkPath) && !resolved.startsWith(projectAbs + path.sep)) continue;
      paths.push(resolved);
    }
  } catch (_) {}
  return paths;
}

// Basename suffix guard: after a basename match, the next character must not be a
// filename character (letter, digit, dot, dash, underscore). This prevents ".env"
// from matching inside ".env.example" while still matching "github-cli/.env.local"
// (exact basename match, nothing follows it).
const FILENAME_CHAR = /^[a-zA-Z0-9._-]/;

function basenameMatchedIn(cmdNorm, basename) {
  const baseLower = basename.toLowerCase();
  const cmdLower  = cmdNorm.toLowerCase();
  let start = 0;
  while (true) {
    const idx = cmdLower.indexOf(baseLower, start);
    if (idx === -1) break;
    const after = cmdNorm.slice(idx + basename.length);
    if (!FILENAME_CHAR.test(after)) return true;
    start = idx + 1;
  }
  return false;
}

// Returns true if command mentions the given absolute path (basename, relative, or absolute).
// Basename matching uses a suffix guard so ".env" does not false-fire on ".env.example".
function commandMentionsPath(command, absPath, projectDir) {
  const cmdNorm = command.replace(/\\/g, '/');

  // Absolute and relative paths: plain substring is safe (they're long/specific enough)
  const candidates = [absPath];
  try {
    const rel = path.relative(projectDir, absPath);
    if (rel && !rel.startsWith('..')) candidates.push(rel);
  } catch (_) {}
  for (const candidate of candidates) {
    const norm = candidate.replace(/\\/g, '/');
    if (cmdNorm.toLowerCase().includes(norm.toLowerCase())) return true;
  }

  return basenameMatchedIn(cmdNorm, path.basename(absPath));
}

module.exports = {
  expandTilde,
  fromGitBash,
  normPath,
  isDescendantOf,
  extractBashWritePaths,
  getTargetPath,
  getTargetPaths,
  isWriteCapableTool,
  normPathLiteral,
  collectProtectedSecretPaths,
  commandMentionsPath,
};
