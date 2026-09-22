// The operator tool is the only supported way to create the deliberately
// opaque files consumed by local password authentication.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as nodeCrypto from 'node:crypto';
import { Readable } from 'node:stream';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFileLocalIdentityStore } from '../adapters/node/local-identities.js';
import { loadConfig } from '../src/config.js';
import { SealError, unseal } from '../src/crypto/secrets.js';
import { localIdentityKey } from '../src/local-identities/index.js';
import {
  main,
  parseArguments,
  provision,
  rekey,
} from '../tools/generate-local-identity.js';

const EMAIL = 'local.user@example.test';
const PASSWORD = 'correct horse battery staple';
const CURRENT_SECRET = 'local-tool-current-secret-not-for-production-0123456789';
const PREVIOUS_SECRET = 'local-tool-previous-secret-not-for-production-0123456789';
const SUBJECT_SALT = 'local-tool-subject-salt-not-for-production';
const REFRESH_TOKEN = 'upstream-refresh-token-kept-out-of-source-json';

function toolEnv(directory, overrides = {}) {
  return {
    SAG_SECRET: CURRENT_SECRET,
    SUBJECT_SALT,
    LOCAL_IDENTITIES_DIR: directory,
    ...overrides,
  };
}

const passwordInput = (value = PASSWORD) => Readable.from([Buffer.from(value + '\n')]);

async function temporaryDirectory(t) {
  const root = await mkdtemp(join(tmpdir(), 'sag-local-identity-tool-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, directory: join(root, 'identities') };
}

function requireArgon2(t) {
  if (typeof nodeCrypto.argon2 === 'function') return true;
  t.skip('this Node.js runtime has no crypto.argon2');
  return false;
}

async function storedRecord(directory, key) {
  const path = join(directory, key + '.json');
  return {
    path,
    raw: await readFile(path, 'utf8'),
    record: JSON.parse(await readFile(path, 'utf8')),
  };
}

test('the local identity tool parses only its documented, secret-safe arguments', async () => {
  assert.deepEqual(
    parseArguments([
      '--email',
      EMAIL,
      '--directory',
      '/srv/identities',
      '--password-stdin',
      '--totp',
      '--backup-codes',
      '4',
      '--claims',
      '/run/claims.json',
      '--upstreams',
      '/run/upstreams.json',
    ]),
    {
      email: EMAIL,
      directory: '/srv/identities',
      password_stdin: true,
      totp: true,
      backup_codes: '4',
      claims: '/run/claims.json',
      upstreams: '/run/upstreams.json',
    },
  );
  assert.deepEqual(parseArguments(['-h']), { h: true });
  assert.throws(() => parseArguments(['--password', 'visible']), /unknown option: --password/);
  assert.throws(() => parseArguments(['--email']), /--email requires a value/);
  assert.throws(() => parseArguments(['--email', '--totp']), /--email requires a value/);

  const output = [];
  assert.equal(await main(['--help'], { output: (line) => output.push(line) }), undefined);
  assert.match(output.join('\n'), /Passwords are accepted only on standard input|--password-stdin/);
  await assert.rejects(
    main(['--rekey', '--email', EMAIL], { env: {}, output: () => {} }),
    /--rekey cannot be combined/,
  );
  await assert.rejects(
    rekey({ directory: '/tmp/unused-local-identities' }, {
      env: toolEnv('/tmp/unused-local-identities'),
      output: () => {},
    }),
    /--rekey requires SAG_SECRET_PREVIOUS/,
  );
});

test('identity creation rejects incomplete or unsafe input before writing', async (t) => {
  const { directory } = await temporaryDirectory(t);
  const options = { email: EMAIL, password_stdin: true, directory };

  await assert.rejects(
    provision(options, { env: { SUBJECT_SALT }, input: passwordInput(), output: () => {} }),
    /SAG_SECRET must contain at least 32 characters/,
  );
  await assert.rejects(
    provision(options, {
      env: { SAG_SECRET: ' '.repeat(40), SUBJECT_SALT },
      input: passwordInput(),
      output: () => {},
    }),
    /SAG_SECRET must contain at least 32 characters/,
  );
  await assert.rejects(
    provision(options, {
      env: { SAG_SECRET: CURRENT_SECRET, SUBJECT_SALT: ' '.repeat(20) },
      input: passwordInput(),
      output: () => {},
    }),
    /SUBJECT_SALT must contain at least 16 characters/,
  );
  await assert.rejects(
    provision(options, {
      env: { SAG_SECRET: CURRENT_SECRET, SUBJECT_SALT: 'too-short' },
      input: passwordInput(),
      output: () => {},
    }),
    /SUBJECT_SALT must contain at least 16 characters/,
  );
  await assert.rejects(
    provision({ email: EMAIL, password_stdin: true }, {
      env: toolEnv(undefined, { LOCAL_IDENTITIES_DIR: '' }),
      input: passwordInput(),
      output: () => {},
    }),
    /--directory or LOCAL_IDENTITIES_DIR is required/,
  );
  await assert.rejects(
    provision({ email: EMAIL, directory }, { env: toolEnv(directory), input: passwordInput(), output: () => {} }),
    /--password-stdin is required/,
  );
  await assert.rejects(
    provision({ ...options, email: 'not-an-address' }, {
      env: toolEnv(directory),
      input: passwordInput(),
      output: () => {},
    }),
    /--email must be an address/,
  );
  await assert.rejects(
    provision({ ...options, backup_codes: '1.5' }, {
      env: toolEnv(directory),
      input: passwordInput(),
      output: () => {},
    }),
    /--backup-codes must be a whole number from 0 to 20/,
  );
  await assert.rejects(
    provision(options, { env: toolEnv(directory), input: passwordInput('too-short'), output: () => {} }),
    /password must contain at least 12 UTF-8 bytes/,
  );
  await assert.rejects(
    provision(options, { env: toolEnv(directory), input: passwordInput('x'.repeat(1025)), output: () => {} }),
    /password must contain at most 1024 UTF-8 bytes/,
  );
  await assert.rejects(
    provision(options, {
      env: toolEnv(directory),
      input: Readable.from([Buffer.from('x'.repeat(2049))]),
      output: () => {},
    }),
    /password must contain at most 1024 UTF-8 bytes/,
  );
  await assert.rejects(
    provision(options, {
      env: toolEnv(directory),
      input: Readable.from([Buffer.from([0xff, 0x0a])]),
      output: () => {},
    }),
    /password must be valid UTF-8/,
  );
});

test('provision writes a private opaque record with sealed TOTP and Argon2id backup codes', async (t) => {
  if (!requireArgon2(t)) return;
  const { root, directory } = await temporaryDirectory(t);
  const claimsPath = join(root, 'claims.json');
  await writeFile(claimsPath, JSON.stringify({ name: 'Jamie Taylor' }));
  const output = [];

  const result = await provision(
    {
      email: EMAIL,
      directory,
      password_stdin: true,
      totp: true,
      backup_codes: '2',
      claims: claimsPath,
    },
    {
      env: toolEnv(directory, {
        SAG_SECRET: '  ' + CURRENT_SECRET + ' \t',
        SUBJECT_SALT: '\n' + SUBJECT_SALT + '  ',
      }),
      input: Readable.from([Buffer.from(PASSWORD + '\r\nignored second line\n')]),
      output: (line) => output.push(line),
    },
  );
  const { path, raw, record } = await storedRecord(directory, result.key);

  assert.equal((await stat(directory)).mode & 0o777, 0o700);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal(record.v, 1);
  assert.equal(record.revision, 1);
  assert.equal(record.security_version, 1);
  assert.deepEqual(record.claims, { name: 'Jamie Taylor' });
  assert.match(record.password, /^\$argon2id\$/);
  assert.equal(record.totp.length, 1);
  assert.equal(record.backup_codes.length, 2);
  assert.equal(record.upstreams.length, 0);
  assert.equal(raw.includes(EMAIL), false);
  assert.equal(raw.includes(PASSWORD), false);
  assert.equal(raw.includes(result.totpSecret), false);
  const runtimeConfig = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    SAG_SECRET: CURRENT_SECRET,
    SUBJECT_SALT,
  });
  assert.equal(result.key, await localIdentityKey(runtimeConfig, EMAIL));

  const store = createFileLocalIdentityStore(directory);
  assert.equal(await store.verifyArgon2id(record.password, PASSWORD), true);
  assert.equal(await store.verifyArgon2id(record.password, 'not the password'), false);
  for (const [index, code] of result.backupCodes.entries()) {
    assert.equal(code.split('-')[0], record.backup_codes[index].id);
    assert.match(record.backup_codes[index].hash, /^\$argon2id\$/);
    assert.equal(await store.verifyArgon2id(record.backup_codes[index].hash, code), true);
    assert.equal(raw.includes(code), false);
  }

  const credential = record.totp[0];
  const totpPayload = await unseal(
    CURRENT_SECRET,
    'local-identity-totp/' + record.id + '/' + credential.id,
    credential.secret,
  );
  assert.deepEqual(totpPayload, {
    v: 1,
    identity_id: record.id,
    credential_id: credential.id,
    secret: result.totpSecret,
  });
  assert.match(result.totpSecret, /^[A-Z2-7]{32}$/);
  assert.ok(output.some((line) => line === 'TOTP secret: ' + result.totpSecret));
  assert.ok(output.some((line) => line.startsWith('TOTP URI: otpauth://totp/')));
  assert.ok(output.includes('Backup codes (shown once):'));
  for (const code of result.backupCodes) assert.ok(output.includes('  ' + code));
});

test('provision refuses to overwrite an existing address', async (t) => {
  if (!requireArgon2(t)) return;
  const { directory } = await temporaryDirectory(t);
  const options = { email: EMAIL, directory, password_stdin: true };
  const first = await provision(options, {
    env: toolEnv(directory),
    input: passwordInput(),
    output: () => {},
  });
  const before = await readFile(join(directory, first.key + '.json'), 'utf8');

  await assert.rejects(
    provision(options, {
      env: toolEnv(directory),
      input: passwordInput('a different strong password'),
      output: () => {},
    }),
    /identity already exists.*nothing was changed/,
  );
  assert.equal(await readFile(join(directory, first.key + '.json'), 'utf8'), before);
});

test('upstream refresh tokens come only from the named environment variable and are sealed', async (t) => {
  if (!requireArgon2(t)) return;
  const { root, directory } = await temporaryDirectory(t);
  const upstreamPath = join(root, 'upstreams.json');
  const link = {
    id: 'work',
    upstream: 'microsoft-example-test',
    issuer: 'https://login.example.test/tenant/v2.0/',
    subject: 'opaque-upstream-subject',
    refresh_token_env: 'WORK_REFRESH_TOKEN',
  };
  await writeFile(upstreamPath, JSON.stringify([link]));

  const result = await provision(
    { email: EMAIL, directory, password_stdin: true, upstreams: upstreamPath },
    {
      env: toolEnv(directory, { WORK_REFRESH_TOKEN: REFRESH_TOKEN }),
      input: passwordInput(),
      output: () => {},
    },
  );
  const { raw, record } = await storedRecord(directory, result.key);
  assert.equal(raw.includes(REFRESH_TOKEN), false);
  assert.equal(raw.includes('WORK_REFRESH_TOKEN'), false);
  assert.equal(record.upstreams.length, 1);
  assert.deepEqual(
    {
      id: record.upstreams[0].id,
      upstream: record.upstreams[0].upstream,
      issuer: record.upstreams[0].issuer,
      subject: record.upstreams[0].subject,
    },
    {
      id: 'work',
      upstream: 'microsoft-example-test',
      issuer: 'https://login.example.test/tenant/v2.0/',
      subject: 'opaque-upstream-subject',
    },
  );
  const refreshPayload = await unseal(
    CURRENT_SECRET,
    'local-identity-refresh/' + record.id + '/work',
    record.upstreams[0].refresh_token,
  );
  assert.deepEqual(refreshPayload, {
    v: 1,
    identity_id: record.id,
    link_id: 'work',
    upstream: 'microsoft-example-test',
    issuer: 'https://login.example.test/tenant/v2.0/',
    subject: 'opaque-upstream-subject',
    token: REFRESH_TOKEN,
  });

  const unsafePath = join(root, 'unsafe-upstreams.json');
  await writeFile(unsafePath, JSON.stringify([{ ...link, refresh_token_env: undefined, refresh_token: REFRESH_TOKEN }]));
  await assert.rejects(
    provision(
      { email: 'other.user@example.test', directory, password_stdin: true, upstreams: unsafePath },
      { env: toolEnv(directory), input: passwordInput(), output: () => {} },
    ),
    /put a refresh token in an environment variable/,
  );
});

test('rekey reseals TOTP and refresh credentials without changing their plaintext', async (t) => {
  if (!requireArgon2(t)) return;
  const { root, directory } = await temporaryDirectory(t);
  const upstreamPath = join(root, 'upstreams.json');
  await writeFile(
    upstreamPath,
    JSON.stringify([
      {
        id: 'work',
        upstream: 'microsoft-example-test',
        issuer: 'https://LOGIN.EXAMPLE.TEST:443/tenant/unused/../v2.0/',
        subject: 'opaque-upstream-subject',
        refresh_token_env: 'WORK_REFRESH_TOKEN',
      },
    ]),
  );
  const provisioned = await provision(
    { email: EMAIL, directory, password_stdin: true, totp: true, upstreams: upstreamPath },
    {
      env: toolEnv(directory, { SAG_SECRET: PREVIOUS_SECRET, WORK_REFRESH_TOKEN: REFRESH_TOKEN }),
      input: passwordInput(),
      output: () => {},
    },
  );
  const before = (await storedRecord(directory, provisioned.key)).record;
  assert.equal(
    before.upstreams[0].issuer,
    'https://LOGIN.EXAMPLE.TEST:443/tenant/unused/../v2.0/',
    'the stored link and its sealed payload retain the exact OIDC issuer identifier',
  );
  const output = [];
  const rotated = await rekey(
    { directory },
    {
      env: toolEnv(directory, { SAG_SECRET_PREVIOUS: PREVIOUS_SECRET }),
      output: (line) => output.push(line),
    },
  );
  assert.deepEqual(rotated, { changed: 1, unchanged: 0 });
  assert.deepEqual(output, ['Rekeyed 1 record(s); 0 already used the current secret.']);

  const after = (await storedRecord(directory, provisioned.key)).record;
  assert.equal(after.revision, before.revision + 1);
  assert.equal(after.password, before.password);
  assert.notEqual(after.totp[0].secret, before.totp[0].secret);
  assert.notEqual(after.upstreams[0].refresh_token, before.upstreams[0].refresh_token);
  const totpPurpose = 'local-identity-totp/' + after.id + '/' + after.totp[0].id;
  const refreshPurpose = 'local-identity-refresh/' + after.id + '/' + after.upstreams[0].id;
  assert.equal((await unseal(CURRENT_SECRET, totpPurpose, after.totp[0].secret)).secret, provisioned.totpSecret);
  assert.equal((await unseal(CURRENT_SECRET, refreshPurpose, after.upstreams[0].refresh_token)).token, REFRESH_TOKEN);
  await assert.rejects(unseal(PREVIOUS_SECRET, totpPurpose, after.totp[0].secret), SealError);
  await assert.rejects(unseal(PREVIOUS_SECRET, refreshPurpose, after.upstreams[0].refresh_token), SealError);

  assert.deepEqual(
    await rekey(
      { directory },
      { env: toolEnv(directory, { SAG_SECRET_PREVIOUS: PREVIOUS_SECRET }), output: () => {} },
    ),
    { changed: 0, unchanged: 1 },
  );
  assert.equal((await storedRecord(directory, provisioned.key)).record.revision, after.revision);
});

test('rekey refuses a missing directory instead of reporting an empty success', async (t) => {
  const { directory } = await temporaryDirectory(t);
  const output = [];
  await assert.rejects(
    rekey(
      { directory },
      {
        env: toolEnv(directory, { SAG_SECRET_PREVIOUS: PREVIOUS_SECRET }),
        output: (line) => output.push(line),
      },
    ),
    /does not exist.*missing identity directory/i,
  );
  assert.deepEqual(output, []);
});
