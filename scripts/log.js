'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');

const PLUGIN_NAME = 'guardrails';
const MAX_LINE_WIDTH = 180;
const MAX_ARCHIVE_FILES = 100;
const MAX_ARCHIVE_DAYS = 30;

// Blocked-commands log is always at HOME level regardless of project cwd.
// One .jsonl file per day for easy date-scoped analysis.
const HOME_LOG_DIR = path.join(os.homedir(), '.claude', 'logs', PLUGIN_NAME);
const BLOCKED_LOG_NAME = `${PLUGIN_NAME}-blocked`;
const BLOCKED_MAX_DAYS = 90;
const BLOCKED_MAX_FILES = 200;

let _logDir = path.join(os.homedir(), '.claude', 'logs', PLUGIN_NAME);
let _sessionPrefix = 'unknown:M';

function getLogPath() {
  return path.join(_logDir, `${PLUGIN_NAME}.log`);
}

function rotateIfNeeded() {
  const currentLog = path.join(_logDir, `${PLUGIN_NAME}.log`);
  try {
    const stat = fs.statSync(currentLog);
    const mtime = stat.mtime;
    const mtimeStamp = `${mtime.getFullYear()}-${String(mtime.getMonth() + 1).padStart(2, '0')}-${String(mtime.getDate()).padStart(2, '0')}`;
    const today = new Date();
    const todayStamp = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
    if (mtimeStamp !== todayStamp) {
      fs.renameSync(currentLog, path.join(_logDir, `${PLUGIN_NAME}-${mtimeStamp}.log`));
    }
  } catch (_) {}
}

function pruneOldLogs() {
  try {
    const now = Date.now();
    const msPerDay = 86400000;
    const archivePattern = new RegExp(`^${PLUGIN_NAME}-\\d{4}-\\d{2}-\\d{2}\\.log$`);
    const files = fs.readdirSync(_logDir)
      .filter(f => archivePattern.test(f))
      .sort();

    const afterAge = files.filter(f => {
      const dateStr = f.replace(`${PLUGIN_NAME}-`, '').replace('.log', '');
      const age = (now - new Date(dateStr).getTime()) / msPerDay;
      if (age > MAX_ARCHIVE_DAYS) {
        try { fs.unlinkSync(path.join(_logDir, f)); } catch (_) {}
        return false;
      }
      return true;
    });

    if (afterAge.length > MAX_ARCHIVE_FILES) {
      for (const f of afterAge.slice(0, afterAge.length - MAX_ARCHIVE_FILES)) {
        try { fs.unlinkSync(path.join(_logDir, f)); } catch (_) {}
      }
    }
  } catch (_) {}
}

function init(event) {
  const cwd = event?.cwd ?? '';
  if (cwd) {
    _logDir = path.join(cwd, '.claude', 'logs', PLUGIN_NAME);
  }
  const sessionId = event?.session_id ? event.session_id.substring(0, 8) : 'unknown';
  const agentSuffix = event?.agent_id
    ? `:A:${event.agent_id.substring(0, 4)}:${event.agent_type || 'unknown'}`
    : ':M';
  _sessionPrefix = `${sessionId}${agentSuffix}`;
}

function write(level, message) {
  try {
    fs.mkdirSync(_logDir, { recursive: true });
    rotateIfNeeded();
    const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const raw = `[${ts}] [${_sessionPrefix}] [${level}] ${message}`;
    const line = (raw.length > MAX_LINE_WIDTH ? raw.substring(0, MAX_LINE_WIDTH) + '...' : raw) + '\n';
    fs.appendFileSync(getLogPath(), line, 'utf8');
    pruneOldLogs();
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// Blocked-command structured log
// One JSON record per blocked/asked command, always written to HOME-level dir
// so all projects are consolidated in one place for analysis.
//
// Entry schema:
//   ts         - ISO timestamp
//   session    - session prefix (session_id + agent suffix)
//   decision   - "deny" | "ask"
//   trigger    - short identifier for the rule that fired (category name,
//                "cross-home-write", "secrets-leak", etc.)
//   project    - absolute path of event.cwd
//   tool       - tool name ("Bash", "Write", "Edit", ...)
//   command    - Bash command (truncated/redacted) or null for non-Bash tools
//   file       - target file path for Write/Edit/NotebookEdit, or null
// ---------------------------------------------------------------------------

function blockedLogPath() {
  const today = new Date();
  const stamp = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
  return path.join(HOME_LOG_DIR, `${BLOCKED_LOG_NAME}-${stamp}.jsonl`);
}

function pruneBlockedLogs() {
  try {
    const now = Date.now();
    const msPerDay = 86400000;
    const archivePattern = new RegExp(`^${BLOCKED_LOG_NAME}-\\d{4}-\\d{2}-\\d{2}\\.jsonl$`);
    const files = fs.readdirSync(HOME_LOG_DIR)
      .filter(f => archivePattern.test(f))
      .sort();

    const remaining = files.filter(f => {
      const dateStr = f.replace(`${BLOCKED_LOG_NAME}-`, '').replace('.jsonl', '');
      const age = (now - new Date(dateStr).getTime()) / msPerDay;
      if (age > BLOCKED_MAX_DAYS) {
        try { fs.unlinkSync(path.join(HOME_LOG_DIR, f)); } catch (_) {}
        return false;
      }
      return true;
    });

    if (remaining.length > BLOCKED_MAX_FILES) {
      for (const f of remaining.slice(0, remaining.length - BLOCKED_MAX_FILES)) {
        try { fs.unlinkSync(path.join(HOME_LOG_DIR, f)); } catch (_) {}
      }
    }
  } catch (_) {}
}

/**
 * @param {object} entry  - { decision, trigger, project, tool, command, file }
 *   All fields except decision and trigger are optional.
 *   command is automatically redacted to '<redacted>' if the string equals that sentinel.
 */
function blocked(entry) {
  try {
    fs.mkdirSync(HOME_LOG_DIR, { recursive: true });
    const record = {
      ts:       new Date().toISOString(),
      session:  _sessionPrefix,
      decision: entry.decision,
      trigger:  entry.trigger,
      project:  entry.project  ?? null,
      tool:     entry.tool     ?? null,
      command:  entry.command  ?? null,
      file:     entry.file     ?? null,
    };
    fs.appendFileSync(blockedLogPath(), JSON.stringify(record) + '\n', 'utf8');
    pruneBlockedLogs();
  } catch (_) {}
}

module.exports = {
  init,
  info:  (msg) => write(' INFO', msg),
  debug: (msg) => write('DEBUG', msg),
  warn:  (msg) => write(' WARN', msg),
  error: (msg) => write('ERROR', msg),
  blocked,
};
