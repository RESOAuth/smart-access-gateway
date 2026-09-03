#!/usr/bin/env node
// Start SAG with its key material kept in a directory.
//
// This is what the container runs. On first start it generates a master secret
// and a signing key into SAG_DATA_DIR and then starts the ordinary Node
// server; on every start after that it reads them back, so restarting does not
// sign everybody out.
//
// Precedence, most specific first: the real environment, then the operator's
// settings file, then the generated secrets. A deployment can therefore
// graduate to a real secret manager one variable at a time.

import { ensureKeyMaterial, SECRETS_FILE, SETTINGS_FILE } from './datadir.js';
import { join } from 'node:path';

const dataDir = process.env.SAG_DATA_DIR || './data';
let values;
let settings;
let generated;
try {
  ({ values, settings, generated } = await ensureKeyMaterial(dataDir, {
    alg: process.env.SIGNING_ALG,
    backend: process.env.SIGNING_BACKEND,
  }));
} catch (err) {
  // A container that cannot write its data directory has one likely cause and
  // one line of fix, so print that rather than a stack trace.
  console.error('\n  ' + String(err.message).split('\n').join('\n  ') + '\n');
  process.exit(1);
}

if (generated.length) {
  console.log('\n  Generated ' + generated.join(', ') + ' in ' + join(dataDir, SECRETS_FILE) + '.');
  console.log('  Keep that directory. Losing it signs everybody out and changes what this instance is.');
}
if (Object.keys(settings).length) {
  console.log('  Read ' + Object.keys(settings).length + ' settings from ' + join(dataDir, SETTINGS_FILE) + '.');
}

for (const [key, value] of Object.entries({ ...values, ...settings })) {
  // eslint-disable-next-line security/detect-object-injection -- key is from generated/configured environment variable keys
  if (process.env[key] === undefined || process.env[key] === '') process.env[key] = value;
}

await import('../adapters/node/server.js');
