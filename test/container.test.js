// The container's promise: generate once, and never again.
//
// An instance that made a new signing key on every start would invalidate
// every session and every token it had issued the moment it restarted, which
// is the sort of thing nobody notices until a deployment restarts under load.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensureKeyMaterial, parseEnvFile, formatEnvFile, SECRETS_FILE, SETTINGS_FILE } from '../tools/datadir.js';
import { loadConfig, assertUsable } from '../src/config.js';
import { newSession, sessionCookie } from '../src/session.js';

const dir = () => mkdtempSync(join(tmpdir(), 'sag-data-'));

test('first start generates everything an instance needs to be itself', async () => {
  const d = dir();
  const { values, generated } = await ensureKeyMaterial(d);
  assert.deepEqual(generated, ['SAG_SECRET', 'SUBJECT_SALT', 'SIGNING_PRIVATE_JWK']);
  assert.ok(values.SAG_SECRET.length >= 60, 'a master secret, not a token');
  assert.equal(JSON.parse(values.SIGNING_PRIVATE_JWK).alg, 'ES256');

  // And the result is a configuration that will actually serve, once the one
  // thing a container cannot generate for itself is set.
  const config = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    EMAIL_PROVIDER: 'ses',
    EMAIL_FROM: 'Sign in <no-reply@id.example.test>',
    SES_REGION: 'eu-west-2',
    ...values,
  });
  assertUsable(config);
  assert.equal(config.problems.length, 0);
});

test('a restart reuses the same key material rather than making new keys', async () => {
  const d = dir();
  const first = await ensureKeyMaterial(d);
  const second = await ensureKeyMaterial(d);
  assert.deepEqual(second.generated, [], 'nothing may be regenerated');
  assert.equal(second.values.SAG_SECRET, first.values.SAG_SECRET);
  assert.equal(second.values.SIGNING_PRIVATE_JWK, first.values.SIGNING_PRIVATE_JWK);
});

test('the secrets file is written for the owner only', async () => {
  const d = dir();
  await ensureKeyMaterial(d);
  const mode = statSync(join(d, SECRETS_FILE)).mode & 0o777;
  assert.equal(mode, 0o600, 'the identity of a deployment is not world readable');
});

test('a signing key held elsewhere is not duplicated into the volume', async () => {
  const d = dir();
  const { values, generated } = await ensureKeyMaterial(d, { backend: 'aws-kms' });
  assert.ok(!generated.includes('SIGNING_PRIVATE_JWK'));
  assert.equal(values.SIGNING_PRIVATE_JWK, undefined);
});

test('the settings file has a say in which key is generated', async () => {
  // An operator who wrote SIGNING_ALG=ES384 there and then found an ES256 key
  // in the volume would have an instance that could not sign anything.
  const d = dir();
  writeFileSync(join(d, SETTINGS_FILE), 'SIGNING_ALG=ES384\n');
  const { values } = await ensureKeyMaterial(d);
  assert.equal(JSON.parse(values.SIGNING_PRIVATE_JWK).alg, 'ES384');
  assert.equal(values.SIGNING_ALG, 'ES384');
});

test('settings are read but never written back', async () => {
  const d = dir();
  writeFileSync(join(d, SETTINGS_FILE), 'UI_ORG_NAME=Borsetshire Council\n# a comment\nOTP_SEND_DAILY_LIMIT=3\n');
  const { settings } = await ensureKeyMaterial(d);
  assert.deepEqual(settings, { UI_ORG_NAME: 'Borsetshire Council', OTP_SEND_DAILY_LIMIT: '3' });
  assert.ok(!readFileSync(join(d, SECRETS_FILE), 'utf8').includes('Borsetshire'), 'settings stay where they were put');
});

test('a signing key survives the round trip through the file, quotes and all', async () => {
  const d = dir();
  const { values } = await ensureKeyMaterial(d);
  const readBack = parseEnvFile(readFileSync(join(d, SECRETS_FILE), 'utf8'));
  assert.deepEqual(JSON.parse(readBack.SIGNING_PRIVATE_JWK), JSON.parse(values.SIGNING_PRIVATE_JWK));
});

test('a value that cannot be written safely is refused rather than mangled', () => {
  // Better to fail here than to write a file that reads back as something
  // else, which would be a silently different deployment identity.
  assert.throws(() => formatEnvFile({ SAG_SECRET: "it's" }), /cannot be written/);
});

test('a ChromeOS Crostini hostname counts as development', async () => {
  // Chrome runs outside the Linux VM, so it reaches a container by name
  // rather than through localhost. Treating penguin.linux.test as production
  // would refuse to start over an http issuer and a console mail provider on
  // the one machine where both are obviously right.
  const config = loadConfig({ SAG_ISSUER: 'http://penguin.linux.test:8787' });
  assert.equal(config.devMode, true);
  assert.deepEqual(config.problems, []);

  // The property that matters is still intact: a real name is still real.
  const real = loadConfig({ SAG_ISSUER: 'http://id.example.com' });
  assert.equal(real.devMode, false);
  assert.ok(real.problems.some((p) => /must only travel over TLS/.test(p)));
});

test('a production issuer is never derived from the request host', () => {
  const config = loadConfig(
    {
      SAG_DEV: 'false',
      SAG_SECRET: 'x'.repeat(48),
      SUBJECT_SALT: 'fixed-salt',
      OTP_ENABLED: 'false',
    },
    { requestUrl: 'https://attacker-chosen-host.example/' },
  );
  assert.ok(config.problems.some((p) => /SAG_ISSUER is required/.test(p)));
});

test('production session cookies are host-prefixed and host-scoped', async () => {
  const production = loadConfig({
    SAG_ISSUER: 'https://id.example.test/identity',
    SAG_SECRET: 'x'.repeat(48),
    SUBJECT_SALT: 'fixed-subject-salt',
    SESSION_COOKIE_NAME: 'custom_session',
  });
  assert.equal(production.session.cookieName, '__Host-custom_session');
  const cookie = await sessionCookie(
    production,
    newSession(production, { email: 'jamie@example.test', acr: 'test', amr: [] }),
  );
  assert.match(cookie, /^__Host-custom_session=/);
  assert.match(cookie, /; Path=\/;/);
  assert.match(cookie, /; Secure/);
  assert.ok(!cookie.includes('Domain='));

  const development = loadConfig({ SAG_ISSUER: 'http://localhost:8787', SESSION_COOKIE_NAME: 'custom_session' });
  assert.equal(development.session.cookieName, 'custom_session');
});
