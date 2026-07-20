'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'pre-tool-use.js');

// ---------------------------------------------------------------------------
// Harness - runs the pre-tool-use script with a given event + optional
// guardrails.json written to a temp dir that is used as event.cwd.
// ---------------------------------------------------------------------------

function runCase(event, guardrailsConfig, extraFiles) {
  let tmpDir = null;

  if (guardrailsConfig) {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardrails-test-'));
    const claudeDir = path.join(tmpDir, '.claude');
    fs.mkdirSync(claudeDir);
    fs.writeFileSync(path.join(claudeDir, 'guardrails.json'), JSON.stringify(guardrailsConfig));
    if (extraFiles) {
      for (const [relPath, content] of Object.entries(extraFiles)) {
        const abs = path.join(tmpDir, relPath);
        fs.mkdirSync(path.dirname(abs), { recursive: true });
        fs.writeFileSync(abs, content);
      }
    }
    event = { ...event, cwd: tmpDir };
  }

  try {
    const result = spawnSync('node', [SCRIPT], {
      input: JSON.stringify(event),
      encoding: 'utf8',
      timeout: 5000,
    });

    if (result.error) throw new Error(`spawn failed: ${result.error.message}`);

    const stdout = (result.stdout || '').trim();
    if (!stdout) return { decision: 'allow', reason: '' };

    const parsed = JSON.parse(stdout);
    return {
      decision: parsed?.hookSpecificOutput?.permissionDecision ?? 'allow',
      reason:   parsed?.hookSpecificOutput?.permissionDecisionReason ?? '',
    };
  } finally {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Case resolution - cases may be plain objects or functions(home) → object
// ---------------------------------------------------------------------------

const HOME = process.env.USERPROFILE || process.env.HOME || os.homedir();

function resolveCase(raw) {
  const event = typeof raw.event === 'function' ? raw.event(HOME) : raw.event;
  return { ...raw, event };
}

// ---------------------------------------------------------------------------
// Suite runner
// knownGap: true  → case is a documented known gap; a mismatch is reported
//                   separately and does NOT count as a failure or exit 1.
// ---------------------------------------------------------------------------

function runSuite(name, rawCases) {
  const cases = rawCases.map(resolveCase);
  let passed = 0;
  let failed = 0;
  let gapCount = 0;
  const failures = [];
  const gaps = [];

  for (const tc of cases) {
    // Known gaps are run but never counted as failures
    if (tc.knownGap) {
      let result;
      try {
        result = runCase(tc.event, tc.guardrailsConfig, tc.extraFiles);
      } catch (e) {
        gaps.push({ tc, error: e.message });
        gapCount++;
        continue;
      }
      if (result.decision !== tc.expect) {
        gaps.push({ tc, got: result });
      } else {
        gaps.push({ tc, fixed: true });
      }
      gapCount++;
      continue;
    }

    let result;
    try {
      result = runCase(tc.event, tc.guardrailsConfig, tc.extraFiles);
    } catch (e) {
      failed++;
      failures.push({ tc, error: e.message });
      continue;
    }

    const decisionOk = result.decision === tc.expect;
    const reasonOk = !tc.expectReasonIncludes || result.reason.includes(tc.expectReasonIncludes);
    if (decisionOk && reasonOk) {
      passed++;
    } else {
      failed++;
      failures.push({ tc, got: result });
    }
  }

  const activeTotal = cases.length - gapCount;
  const status = failed === 0 ? '✓' : '✗';
  const gapSuffix = gapCount > 0 ? `  (+ ${gapCount} known gaps)` : '';
  console.log(`\n${status} ${name} - ${passed}/${activeTotal} passed${gapSuffix}`);

  for (const { tc, got, error } of failures) {
    if (error) {
      console.log(`    ✗ ${tc.description}`);
      console.log(`        ERROR: ${error}`);
    } else {
      console.log(`    ✗ ${tc.description}`);
      console.log(`        expected: ${tc.expect}  got: ${got.decision}`);
      if (tc.expectReasonIncludes && !got.reason.includes(tc.expectReasonIncludes))
        console.log(`        reason must include: "${tc.expectReasonIncludes}"`);
      if (got.reason) console.log(`        reason: ${got.reason.split('\n')[0]}`);
    }
  }

  const fixedGaps = gaps.filter(g => g.fixed);
  const openGaps  = gaps.filter(g => !g.fixed);
  if (fixedGaps.length > 0) {
    console.log(`    ⬆ Known gaps now passing (promote to real tests):`);
    for (const { tc } of fixedGaps) {
      console.log(`      · ${tc.description}`);
    }
  }
  if (openGaps.length > 0) {
    console.log(`    ⚠ Known gaps still open:`);
    for (const { tc, got, error } of openGaps) {
      if (error) {
        console.log(`      · ${tc.description} - ERROR: ${error}`);
      } else if (got && got.decision !== tc.expect) {
        const reason = tc.gapReason ? `\n          ${tc.gapReason}` : '';
        console.log(`      · ${tc.description}${reason}`);
      }
    }
  }

  return { passed, failed, total: activeTotal, gapCount };
}

// ---------------------------------------------------------------------------
// Load all suites from cases/
// ---------------------------------------------------------------------------

const CASES_DIR = path.join(__dirname, 'cases');
const suiteFiles = fs.readdirSync(CASES_DIR)
  .filter((f) => f.endsWith('.js'))
  .sort();

let totalPassed = 0;
let totalFailed = 0;
let totalCases  = 0;
let totalGaps   = 0;

console.log('guardrails test suite');
console.log('=======================');

for (const file of suiteFiles) {
  const suiteName = file.replace(/\.js$/, '');
  const cases = require(path.join(CASES_DIR, file));
  const { passed, failed, total, gapCount } = runSuite(suiteName, cases);
  totalPassed += passed;
  totalFailed += failed;
  totalCases  += total;
  totalGaps   += gapCount;
}

console.log('\n=======================');
if (totalGaps > 0) {
  console.log(`⚠ ${totalGaps} known gaps documented (not failures)`);
}
if (totalFailed === 0) {
  console.log(`✓ All ${totalCases} active tests passed`);
} else {
  console.log(`✗ ${totalFailed}/${totalCases} active tests FAILED`);
  process.exit(1);
}
