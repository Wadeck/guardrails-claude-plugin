'use strict';
const path = require('path');
const log = require('./log');

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  let event;
  try {
    event = JSON.parse(input);
  } catch (e) {
    process.exit(0);
  }

  log.init(event);

  const pluginJson = path.join(__dirname, '..', '.claude-plugin', 'plugin.json');
  let version = 'unknown';
  try {
    version = JSON.parse(require('fs').readFileSync(pluginJson, 'utf8')).version;
  } catch (_) {}

  log.info(`guardrails v${version} - session started | cwd=${event?.cwd ?? '?'}`);
}

main().catch(() => process.exit(0));
