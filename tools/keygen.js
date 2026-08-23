#!/usr/bin/env node
// Generate the key material a real deployment needs.
//
// The output is deliberately copy-pasteable environment variables rather than
// files, because that is how a Worker, a Lambda and a container all take
// secrets. Nothing is written to disk unless asked for, so a key cannot be
// left lying in a repository by accident.

import { writeFileSync } from 'node:fs';
import { generateSigningKey, randomSecret } from '../src/keys/generate.js';
import { algEnvSuffix } from '../src/config.js';

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf('--' + name);
  if (i === -1) return fallback;
  const next = args[i + 1];
  return next && !next.startsWith('--') ? next : true;
};

if (flag('help', false) || args.includes('-h')) {
  console.log(`
  Generate keys and secrets for a SAG deployment.

    npm run keygen                        ES256 signing key and a master secret
    npm run keygen -- --alg ML-DSA-65     a post-quantum signing key instead
    npm run keygen -- --alg ES256,ML-DSA-44
                                          a classical key and a post-quantum
                                          one, published side by side
    npm run keygen -- --secret-only       just the symmetric secrets
    npm run keygen -- --out keys.json     also write the private JWKs to a file

  The signing key is asymmetric and identifies this deployment; the master
  secret is symmetric and protects sessions, transactions and codes. They are
  separate because they rotate on completely different schedules: a secret can
  be rolled at will, whereas replacing a signing key means relying parties
  re-reading the JWKS.
`);
  process.exit(0);
}

const lines = [];
const say = (s = '') => lines.push(s);

say('');
say('# SAG key material - generated ' + new Date().toISOString());
say('#');
say('# Store every value below as a secret. Anything marked SIGNING_PRIVATE_JWK');
say('# or SAG_SECRET is enough on its own to impersonate this deployment.');
say('');

const secretOnly = Boolean(flag('secret-only', false));
const results = [];

if (!secretOnly) {
  const algs = String(flag('alg', 'ES256'))
    .split(/[,\s]+/)
    .filter(Boolean);
  for (const alg of algs) {
    try {
      results.push(await generateSigningKey(alg));
    } catch (err) {
      console.error('  ! ' + err.message);
      process.exitCode = 1;
    }
  }
  if (results.length === 0) {
    console.error('\n  No keys could be generated.\n');
    process.exit(1);
  }

  const [primary, ...additional] = results;
  say('SIGNING_ALG=' + primary.alg);
  say('SIGNING_PRIVATE_JWK=' + JSON.stringify(primary.privateJwk));
  if (additional.length) {
    say('SIGNING_ADDITIONAL_ALGS=' + additional.map((r) => r.alg).join(','));
    for (const extra of additional) {
      say('SIGNING_PRIVATE_JWK_' + algEnvSuffix(extra.alg) + '=' + JSON.stringify(extra.privateJwk));
    }
  }
  say('');
}

say('SAG_SECRET=' + randomSecret());
say('');
say('# Only needed with SUBJECT_TYPE=pairwise. Never change it once relying');
say('# parties have stored subjects, or every account is orphaned.');
say('# SUBJECT_SALT=' + randomSecret());
say('');

if (!secretOnly) {
  say('# Public half, for reference. SAG publishes this at /jwks.json itself,');
  say('# so it does not need to be configured anywhere.');
  say('# ' + JSON.stringify({ keys: results.map((r) => r.publicJwk) }));
  say('');
  const pq = results.filter((r) => r.family === 'post-quantum');
  if (pq.length === 0) {
    say('# No post-quantum signing key was generated. To publish one alongside');
    say('# the classical key, so relying parties can migrate at their own pace:');
    say('#   npm run keygen -- --alg ' + results[0].alg + ',ML-DSA-44');
    say('');
  }
}

const out = flag('out', false);
if (out && typeof out === 'string') {
  writeFileSync(
    out,
    JSON.stringify({ generated: new Date().toISOString(), keys: results.map((r) => r.privateJwk) }, null, 2) + '\n',
    { mode: 0o600 },
  );
  say('# Private JWKs also written to ' + out + ' with mode 600. Do not commit it.');
  say('');
}

console.log(lines.join('\n'));
