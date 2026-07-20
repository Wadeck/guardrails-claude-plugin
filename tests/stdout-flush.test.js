'use strict';

// stdout-flush: verify that the hook's JSON response is received by the pipe
// BEFORE process.exit(0) closes it - for every decision type.
//
// The race condition: process.stdout.write() is async on piped streams.
// If process.exit(0) fires before the kernel flushes the buffer, Claude Code
// receives an empty pipe and treats it as "allow" - silently bypassing ask/deny.
//
// This test uses spawn() (not spawnSync) to observe data vs close events in
// real time. If 'data' always arrives before 'close', the flush is safe.
// Run N_RUNS times to surface the race (it's timing-dependent).

const { spawn } = require('child_process');
const path = require('path');
const os   = require('os');

const SCRIPT   = path.join(__dirname, '..', 'scripts', 'pre-tool-use.js');
const N_RUNS   = 30;
const HOME     = process.env.USERPROFILE || process.env.HOME || os.homedir();
const PROJ_DIR = 'C:\\Workspace\\myproject';

// Events that should produce ask or deny (the at-risk decisions)
const CASES = [
  {
    label: 'memory-write → ask',
    event: {
      tool_name: 'Write',
      tool_input: { file_path: `${PROJ_DIR}\\.claude\\memory\\feedback.md`, content: 'x' },
      cwd: PROJ_DIR,
    },
    expectDecision: 'ask',
  },
  {
    label: 'rm → deny',
    event: {
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /tmp/test' },
      cwd: PROJ_DIR,
    },
    expectDecision: 'deny',
  },
];

function runOnce(event) {
  return new Promise((resolve) => {
    const child = spawn('node', [SCRIPT], { stdio: ['pipe', 'pipe', 'pipe'] });

    let dataReceived = false;
    let dataTs = null;
    let closeTs = null;
    let stdout = '';

    child.stdout.on('data', (chunk) => {
      if (!dataReceived) { dataReceived = true; dataTs = Date.now(); }
      stdout += chunk.toString();
    });

    child.on('close', () => {
      closeTs = Date.now();
      let decision = '(empty)';
      try {
        const parsed = JSON.parse(stdout.trim());
        decision = parsed?.hookSpecificOutput?.permissionDecision ?? '(no decision)';
      } catch (_) {}
      resolve({ dataReceived, dataTs, closeTs, decision, stdout: stdout.trim() });
    });

    child.stdin.write(JSON.stringify(event));
    child.stdin.end();
  });
}

async function main() {
  let totalFailed = 0;
  let totalPassed = 0;

  console.log('stdout-flush test - race condition detection');
  console.log(`Running ${N_RUNS} iterations per case\n`);

  for (const { label, event, expectDecision } of CASES) {
    let raceCount = 0;
    let wrongDecision = 0;

    for (let i = 0; i < N_RUNS; i++) {
      const r = await runOnce(event);

      if (!r.dataReceived) {
        raceCount++;
        continue;
      }
      if (r.decision !== expectDecision) {
        wrongDecision++;
      }
    }

    const failed = raceCount > 0 || wrongDecision > 0;
    if (failed) {
      totalFailed++;
      console.log(`  ✗ ${label}`);
      if (raceCount > 0)
        console.log(`      stdout empty before close: ${raceCount}/${N_RUNS} runs  ← RACE CONDITION`);
      if (wrongDecision > 0)
        console.log(`      wrong decision: ${wrongDecision}/${N_RUNS} (expected ${expectDecision})`);
    } else {
      totalPassed++;
      console.log(`  ✓ ${label} - ${N_RUNS}/${N_RUNS} runs: data always before close`);
    }
  }

  console.log(`\n${totalFailed === 0 ? '✓ All' : '✗'} ${totalPassed + totalFailed} flush tests ${totalFailed === 0 ? 'passed' : `- ${totalFailed} FAILED`}`);
  process.exit(totalFailed > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
