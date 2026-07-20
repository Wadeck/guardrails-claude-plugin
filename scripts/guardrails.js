'use strict';
const fs = require('fs');
const path = require('path');

/**
 * Loads .claude/guardrails.json from the project dir.
 * Returns null if absent or malformed.
 */
function loadConfig(projectDir) {
  const configPath = path.join(projectDir, '.claude', 'guardrails.json');
  try {
    const raw = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

// Minimum length for a base64 fingerprint to be usable without excessive false positives.
const MIN_B64_FINGERPRINT_LENGTH = 8;

/**
 * Precomputes base64 fingerprints for a secret value, covering all 3 byte-alignment offsets
 * (0, 1, 2 mod 3) by prepending 0-3 padding bytes before encoding.
 *
 * Why this is needed: base64 encodes groups of 3 bytes. When a secret is embedded inside a
 * longer string (e.g. "user:secret" in curl Basic auth), the secret starts at a byte offset
 * that may not be divisible by 3. This shifts the base64 character boundaries, producing a
 * completely different encoding than base64(secret) alone. By generating one fingerprint per
 * alignment, we cover every possible position the secret can occupy inside a base64 payload.
 *
 * Example: base64("username:password") contains "cGFzc3dvcmQ" (alignment 0 fingerprint of
 * "password"), but base64("user:password") contains "YXNzd29yZA" (alignment 2 fingerprint).
 *
 * Returns a deduplicated array of fingerprint strings (alignment 0 and 3 are identical).
 */
function buildBase64Fingerprints(value) {
  const fingerprints = new Set();
  for (let n = 0; n <= 3; n++) {
    const b64 = Buffer.from('X'.repeat(n) + value).toString('base64');
    // Skip the leading base64 groups that mix prefix bytes with secret bytes.
    const skipChars = Math.ceil(n / 3) * 4;
    const fingerprint = b64.slice(skipChars).replace(/=+$/, '');
    if (fingerprint.length >= MIN_B64_FINGERPRINT_LENGTH) {
      fingerprints.add(fingerprint);
    }
  }
  return [...fingerprints];
}

// ---------------------------------------------------------------------------
// Format parsers
// ---------------------------------------------------------------------------

/**
 * Detects the file format from its extension, or returns the explicit override tag.
 * Supported: 'env' (default), 'properties'.
 * Returns 'unknown' if an explicit tag is given but not recognised.
 */
function detectFormat(filePath, explicitTag) {
  if (explicitTag) {
    return ['env', 'properties'].includes(explicitTag) ? explicitTag : 'unknown';
  }
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.properties') return 'properties';
  // .env, .env.local, .env.production, .secrets, no extension → env
  return 'env';
}

/**
 * Parses an .env-style file: KEY=VALUE, optional `export `, single/double quoted values,
 * inline # comments (outside quotes), empty lines and # full-line comments ignored.
 * Lines starting with @ are skipped (link directives, handled by loadSecrets).
 */
function parseEnv(content) {
  const entries = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('@')) continue;
    const withoutExport = trimmed.replace(/^export\s+/, '');
    const eq = withoutExport.indexOf('=');
    if (eq < 1) continue;
    const key = withoutExport.slice(0, eq).trim();
    let value = withoutExport.slice(eq + 1).trim();
    // If value starts with a quote, find the matching closing quote and extract between them.
    // This correctly handles KEY="secret" # comment - the comment is outside the quotes.
    if (value.startsWith('"') || value.startsWith("'")) {
      const q = value[0];
      const closeIdx = value.indexOf(q, 1);
      if (closeIdx !== -1) {
        value = value.slice(1, closeIdx);
      }
      // No closing quote found - leave as-is (malformed, best effort)
    } else {
      // Unquoted: strip inline comment: KEY=value # comment
      const commentIdx = value.indexOf(' #');
      if (commentIdx !== -1) value = value.slice(0, commentIdx).trim();
    }
    if (value.length > 0) entries.push({ key, value });
  }
  return entries;
}

/**
 * Parses a Java .properties file: KEY = VALUE or KEY: VALUE or KEY VALUE.
 * Full-line comments start with # or !. No inline comments per spec.
 */
function parseProperties(content) {
  const entries = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) continue;
    // Separator: first unescaped = or : or whitespace
    // Key pattern extended to include ':' - valid in Java .properties (e.g. app:db.password)
    const match = trimmed.match(/^([\w.\-:]+)\s*[=:\s]\s*(.*)/);
    if (!match) continue;
    const key = match[1].trim();
    const value = match[2].trim();
    if (value.length > 0) entries.push({ key, value });
  }
  return entries;
}

/**
 * Dispatches to the correct parser for the given format.
 * Returns { entries, format } - format is what was actually used.
 */
function parseFile(content, format) {
  if (format === 'properties') return { entries: parseProperties(content), format };
  // 'env' or fallback for anything else
  return { entries: parseEnv(content), format: 'env' };
}

// ---------------------------------------------------------------------------
// Secret loader
// ---------------------------------------------------------------------------

/**
 * Loads secret values from the secrets file declared in config.
 *
 * Main file (guardrails.secrets) uses the env format.
 * Lines starting with @ declare linked files:
 *   @path/to/file              - format auto-detected from extension
 *   @path/to/file [properties] - explicit format override
 * Linked file paths are absolute or relative to projectDir.
 *
 * @param {string} projectDir
 * @param {object} config
 * @param {object} [callbacks]
 * @param {(msg: string) => void} [callbacks.onWarn]  - unreadable / unknown-format linked file
 * @param {(msg: string) => void} [callbacks.onInfo]  - per-file parse summary (format + count)
 * Returns an array of { key, value, b64Fingerprints } objects.
 */
// Cap secrets-file size to prevent DoS via /dev/zero, oversized config-driven
// values, or hostile UNC paths. 10 MB is far above any legitimate secrets file.
const SECRETS_FILE_MAX_BYTES = 10 * 1024 * 1024;

// Read a secrets file with three guards:
//   1. fs.statSync to reject non-regular-files (FIFOs, devices, sockets, dirs).
//      A FIFO with no writer would block readFileSync indefinitely; /dev/zero
//      and /dev/urandom would read into OOM. Both have been seen in audits.
//   2. Size cap (10 MB) - secrets files are tiny in practice.
//   3. Regular fs.readFileSync (after the stat passes), which is safe.
// Returns the file content string, or null if the file is unsafe / unreadable.
function safeReadSecretFile(filePath, onWarn) {
  let st;
  try { st = fs.statSync(filePath); } catch (_) { return null; }
  if (!st.isFile()) {
    onWarn && onWarn(`Refusing to read non-regular secrets file (FIFO / device / socket / dir): ${filePath}`);
    return null;
  }
  if (st.size > SECRETS_FILE_MAX_BYTES) {
    onWarn && onWarn(`Refusing to read oversized secrets file (${st.size} > ${SECRETS_FILE_MAX_BYTES} bytes): ${filePath}`);
    return null;
  }
  try { return fs.readFileSync(filePath, 'utf8'); } catch (_) { return null; }
}

function loadSecrets(projectDir, config, { onWarn = () => {}, onInfo = () => {} } = {}) {
  if (!config?.secrets?.file) return [];
  const secretsPath = path.isAbsolute(config.secrets.file)
    ? config.secrets.file
    : path.join(projectDir, config.secrets.file);
  const mainContent = safeReadSecretFile(secretsPath, onWarn);
  if (mainContent === null) return [];

  const secrets = [];

  const MIN_SECRET_LENGTH = 8;

  const addEntries = (entries, label, format) => {
    const before = secrets.length;
    for (const { key, value } of entries) {
      if (value.length < MIN_SECRET_LENGTH) {
        // Too short to match reliably - would cause false positives on common substrings
        onWarn(`Secret '${key}' in ${label} is shorter than ${MIN_SECRET_LENGTH} chars and will be ignored`);
        continue;
      }
      secrets.push({ key, value, b64Fingerprints: buildBase64Fingerprints(value) });
    }
    onInfo(`Secrets loaded | file=${label} format=${format} count=${secrets.length - before}`);
  };

  // Parse main file (always env format - it's our own format)
  const { entries: mainEntries } = parseFile(mainContent, 'env');
  addEntries(mainEntries, path.basename(secretsPath), 'env');

  // Resolve @ links
  for (const line of mainContent.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('@')) continue;
    // Syntax: @filepath [format]
    const rest = trimmed.slice(1).trim();
    const tagMatch = rest.match(/^(.*?)\s+\[(\w+)\]$/);
    const linkPath = tagMatch ? tagMatch[1].trim() : rest;
    const explicitTag = tagMatch ? tagMatch[2] : null;

    const resolved = path.isAbsolute(linkPath)
      ? linkPath
      : path.join(projectDir, linkPath);

    // Skip relative links that resolve outside projectDir (path traversal via ../).
    // The + path.sep prevents false matches on sibling dirs sharing a common prefix
    // (e.g. /project-evil would not be confused for /project).
    if (!path.isAbsolute(linkPath) && !resolved.startsWith(path.resolve(projectDir) + path.sep)) {
      onWarn(`Linked secrets file resolves outside project dir, skipping: ${resolved}`);
      continue;
    }

    const format = detectFormat(resolved, explicitTag);
    if (format === 'unknown') {
      onWarn(`Linked secrets file has unknown format tag '[${explicitTag}]', skipping: ${resolved}`);
      continue;
    }

    const linkedContent = safeReadSecretFile(resolved, onWarn);
    if (linkedContent === null) {
      onWarn(`Linked secrets file not readable or unsafe: ${resolved}`);
      continue;
    }

    const { entries: linkedEntries, format: usedFormat } = parseFile(linkedContent, format);
    addEntries(linkedEntries, resolved, usedFormat);
  }

  return secrets;
}

/**
 * Returns the first secret whose value (or a base64 fingerprint of it) appears in the command,
 * or null.
 */
function findLeakedSecret(command, secrets) {
  for (const s of secrets) {
    if (command.includes(s.value)) return s;
    for (const fp of s.b64Fingerprints) {
      if (command.includes(fp)) return s;
    }
  }
  return null;
}

/**
 * Walks up from dir until a .git directory is found. Returns that directory, or null.
 */
function findGitRoot(dir) {
  let current = path.resolve(dir);
  while (true) {
    if (fs.existsSync(path.join(current, '.git'))) return current;
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

/**
 * Reads all .gitignore lines (non-empty, non-comment) from a file. Returns [] if absent.
 */
function readGitignorePatterns(gitignorePath) {
  try {
    return fs.readFileSync(gitignorePath, 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
  } catch (_) {
    return [];
  }
}

/**
 * Tests whether a single .gitignore pattern covers a given relative path.
 * Best-effort only - does not implement the full gitignore spec. Known limitations:
 *   - Negation patterns (!pattern) are not supported and will be silently ignored
 *   - Re-inclusion after negation is not handled
 * This is intentional: implementing a full gitignore engine is out of scope.
 * The goal is to catch the common accidental cases, not to be exhaustive.
 * Supports: exact matches, filename-only matches, * (single segment), ** (any depth).
 */
function gitignorePatternMatches(pattern, relPath) {
  const norm = pattern.replace(/\\/g, '/').replace(/^\//, '');
  const fileName = path.basename(relPath);

  // Exact matches
  if (norm === relPath || norm === fileName || relPath.endsWith('/' + norm)) return true;

  // Glob: convert to regexp
  // Escape all regex special chars except * which we handle manually
  const reStr = norm
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\x00')        // placeholder for **
    .replace(/\*/g, '[^/]*')         // * → any chars except /
    .replace(/\x00/g, '.*');         // ** → any chars including /

  try {
    const re = new RegExp('^' + reStr + '$');
    if (re.test(relPath) || re.test(fileName)) return true;
  } catch (_) { /* malformed pattern - skip */ }

  return false;
}

function checkSecretsGitignored(projectDir, config) {
  const secretsFile = config?.secrets?.file;
  if (!secretsFile) return { gitignored: true, secretsRelPath: null };

  // An absolute path is outside the project - we can't check its gitignore, treat as gitignored
  // to avoid blocking all commands for a legitimate global secrets file.
  if (path.isAbsolute(secretsFile)) return { gitignored: true, secretsRelPath: secretsFile };

  // Normalise to forward-slash relative path for matching; strip leading ./ if present
  const secretsRelPath = secretsFile.replace(/\\/g, '/').replace(/^\.\//, '');

  const dirsToCheck = [projectDir];
  const gitRoot = findGitRoot(projectDir);
  if (gitRoot && path.resolve(gitRoot) !== path.resolve(projectDir)) {
    dirsToCheck.push(gitRoot);
  }

  for (const dir of dirsToCheck) {
    const patterns = readGitignorePatterns(path.join(dir, '.gitignore'));
    for (const pattern of patterns) {
      if (gitignorePatternMatches(pattern, secretsRelPath)) {
        return { gitignored: true, secretsRelPath };
      }
    }
  }

  return { gitignored: false, secretsRelPath };
}

// ---------------------------------------------------------------------------
// Protected files - glob-based write protection
// ---------------------------------------------------------------------------

/**
 * Converts a glob pattern (relative to project root) to a RegExp.
 * Semantics:
 *   **  → matches any sequence of characters including /
 *   *   → matches any sequence of characters except /
 *   ?   → matches any single character except /
 *   .   → literal dot
 * The pattern is anchored at both ends.
 */
function globToRegExp(pattern) {
  const norm = pattern.replace(/\\/g, '/');

  // Expand brace alternation {a,b,c} into a regex alternation (?:a|b|c).
  // Only handles simple non-nested brace sets; nested braces fall through to
  // literal matching (safe: they just won't match, not a security issue).
  function expandBraces(s) {
    const open = s.indexOf('{');
    if (open === -1) return [s];
    const close = s.indexOf('}', open);
    if (close === -1) return [s];
    const prefix = s.slice(0, open);
    const suffix = s.slice(close + 1);
    const alts = s.slice(open + 1, close).split(',');
    const results = [];
    for (const alt of alts) {
      for (const expanded of expandBraces(prefix + alt + suffix)) {
        results.push(expanded);
      }
    }
    return results;
  }

  const expanded = expandBraces(norm);
  if (expanded.length > 1) {
    // Build one regex per expansion, union them.
    const parts = expanded.map((p) => globToRegExp(p).source.slice(1, -1)); // strip ^...$
    return new RegExp('^(?:' + parts.join('|') + ')$');
  }

  let reStr = '';
  let i = 0;
  while (i < norm.length) {
    if (norm[i] === '*' && norm[i + 1] === '*') {
      reStr += '.*';
      i += 2;
      // skip a trailing / after ** so that "src/**" matches "src/foo" (not "src//foo")
      if (norm[i] === '/') i++;
    } else if (norm[i] === '*') {
      reStr += '[^/]*';
      i++;
    } else if (norm[i] === '?') {
      reStr += '[^/]';
      i++;
    } else {
      // escape all regex metacharacters
      reStr += norm[i].replace(/[.+^${}()|[\]\\]/g, '\\$&');
      i++;
    }
  }
  return new RegExp('^' + reStr + '$');
}

const VALID_DECISIONS = new Set(['deny', 'ask', 'allow']);

/**
 * Evaluates the protected_files rules against a relative file path.
 * Returns the most restrictive decision that matches, or null if nothing matches.
 * Invalid rules (missing glob, unknown decision) are silently skipped.
 *
 * @param {Array}  rules    - config.protected_files
 * @param {string} relPath  - path relative to project root, forward-slash normalised
 * @returns {'deny'|'ask'|'allow'|null}
 */
function matchProtectedFiles(rules, relPath) {
  if (!Array.isArray(rules) || rules.length === 0) return null;
  const RANK = { deny: 2, ask: 1, allow: 0 };
  let worstDecision = null;

  for (const rule of rules) {
    if (!rule || typeof rule !== 'object' || typeof rule.glob !== 'string') continue;
    const decision = (rule.decision ?? '').toLowerCase();
    if (!VALID_DECISIONS.has(decision)) continue;

    let re;
    try {
      // Lowercase the glob: normPath lowercases relPath for case-insensitive
      // comparison on Windows. Without this lowering, a rule like `**/*.PEM`
      // produces a case-sensitive regex `\.PEM$` that never matches `.pem`.
      re = globToRegExp(rule.glob.toLowerCase());
    } catch (_) {
      continue;
    }

    if (re.test(relPath)) {
      if (worstDecision === null || RANK[decision] > RANK[worstDecision]) {
        worstDecision = decision;
      }
    }
  }

  return worstDecision;
}

module.exports = { loadConfig, loadSecrets, findLeakedSecret, checkSecretsGitignored, matchProtectedFiles };
