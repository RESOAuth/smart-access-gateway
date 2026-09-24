// Portable local-identity primitives: strict records, plaintext TOTP, and
// sealed refresh credentials. The filesystem and Argon2 have their own tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { seal } from '../src/crypto/secrets.js';
import {
  createLocalIdentityStore,
  localIdentityKey,
  newCredentialId,
  newLocalIdentityId,
  parseLocalIdentityRecord,
  sealUpstreamRefreshToken,
} from '../src/local-identities/index.js';
import {
  decodeBase32,
  encodeBase32,
  totpForStep,
  verifyTotp,
} from '../src/local-identities/totp.js';

const ISSUER = 'http://localhost:8787';
const CURRENT_SECRET = 'current-local-secret-'.repeat(3);
const PREVIOUS_SECRET = 'previous-local-secret-'.repeat(3);
const SUBJECT_SALT = 'local-index-secret-'.repeat(3);
const EMAIL = 'jamie.taylor@example.test';
const RECORD_ID = 'local-record-id';
const PHC = '$argon2id$v=19$m=65536,t=3,p=1$c2FsdC1sb2NhbC10ZXN0$dmVyaWZpZXItdGVzdC12YWx1ZQ';

function configWith(overrides = {}) {
  return loadConfig({
    SAG_ISSUER: ISSUER,
    SAG_SECRET: CURRENT_SECRET,
    SUBJECT_SALT,
    STATE_STORE_BACKEND: 'memory',
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
    ...overrides,
  });
}

function document(overrides = {}) {
  return {
    v: 1,
    id: RECORD_ID,
    revision: 1,
    security_version: 1,
    password: PHC,
    totp: [],
    backup_codes: [],
    upstreams: [],
    ...overrides,
  };
}

function memoryBinding(initial = new Map(), verifyArgon2id = async () => false) {
  const records = new Map(initial);
  return {
    records,
    verifyArgon2id,
    async get(key) {
      return records.get(key);
    },
    async replace(key, expectedRevision, next) {
      if ((records.get(key)?.revision ?? 0) !== expectedRevision) return false;
      records.set(key, next);
      return true;
    },
    async list() {
      return [...records.keys()].map((key) => key + '.json');
    },
  };
}

test('base32 and RFC 6238 TOTP vectors cover every supported digest', async () => {
  const sha1 = new TextEncoder().encode('12345678901234567890');
  const sha256 = new TextEncoder().encode('12345678901234567890123456789012');
  const sha512 = new TextEncoder().encode(
    '1234567890123456789012345678901234567890123456789012345678901234',
  );
  const encoded = encodeBase32(sha1);
  assert.equal(encoded, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.deepEqual(decodeBase32(encoded.toLowerCase() + '===='), sha1);
  assert.deepEqual(decodeBase32('GEZD-GNBV GY3TQOJQGEZDGNBVGY3TQOJQ'), sha1);
  assert.equal(encodeBase32(new Uint8Array([0xff])), '74');
  assert.equal(encodeBase32(new Uint8Array([0xff]).buffer), '74');

  assert.equal(await totpForStep(sha1, 1, { algorithm: 'SHA-1', digits: 8 }), '94287082');
  assert.equal(await totpForStep(sha256, 1, { algorithm: 'sha256', digits: 8 }), '46119246');
  assert.equal(await totpForStep(sha512, 1, { algorithm: 'SHA512', digits: 8 }), '90693936');

  await assert.rejects(() => totpForStep(sha1, -1), /invalid TOTP time-step/);
  await assert.rejects(() => totpForStep(sha1, 1.5), /invalid TOTP time-step/);
  await assert.rejects(() => totpForStep(sha1, 1, { digits: 7 }), /TOTP digits/);
  await assert.rejects(() => totpForStep(sha1, 1, { algorithm: 'MD5' }), /unsupported TOTP algorithm/);
  assert.throws(() => decodeBase32(''), /invalid base32/);
  assert.throws(() => decodeBase32('NOT!BASE32'), /invalid base32/);
  assert.throws(() => decodeBase32('MZXW6YTBOI'), /at least 80 bits/);
});

test('TOTP verification accepts configured skew once and rejects malformed policy', async () => {
  const secret = new TextEncoder().encode('12345678901234567890');
  const code = await totpForStep(secret, 1, { digits: 8 });
  assert.equal(
    await verifyTotp({ secret, code: '9428-7082', now: 59_000, digits: 8, skew: 0 }),
    1,
  );
  assert.equal(
    await verifyTotp({ secret, code: ' 9428 7082 ', now: 89_000, digits: 8, skew: 1 }),
    1,
  );
  assert.equal(
    await verifyTotp({ secret, code, now: 59_000, digits: 8, skew: 0, lastUsedStep: 1 }),
    undefined,
  );
  assert.equal(await verifyTotp({ secret, code: 'not-a-code', digits: 8 }), undefined);
  assert.equal(await verifyTotp({ secret, code: '00000000', now: 59_000, digits: 8, skew: 0 }), undefined);

  const stepZero = await totpForStep(secret, 0, { digits: 8 });
  assert.equal(await verifyTotp({ secret, code: stepZero, now: 0, digits: 8, skew: 1 }), 0);
  await assert.rejects(() => verifyTotp({ secret, code, digits: 8, period: 14 }), /invalid TOTP period/);
  await assert.rejects(() => verifyTotp({ secret, code, digits: 8, period: 121 }), /invalid TOTP period/);
  await assert.rejects(() => verifyTotp({ secret, code, digits: 8, skew: -1 }), /invalid TOTP skew/);
  await assert.rejects(() => verifyTotp({ secret, code, digits: 8, skew: 6 }), /invalid TOTP skew/);
});

test('local identity records are bounded, canonical and reject malformed credentials', () => {
  const config = configWith();
  const valid = document({
    disabled: true,
    claims: { name: 'Jamie Taylor' },
    totp: [
      {
        id: 'phone',
        label: 'x'.repeat(140),
        secret: 'gezd-gnbv gy3tqojqgezdgnbvgy3tqojq====',
        algorithm: 'sha-256',
        digits: 8,
        period: 60,
        last_used_step: 4,
      },
    ],
    backup_codes: [{ id: 'recovery', hash: PHC }],
    upstreams: [
      {
        upstream: 'google:example-test',
        issuer: 'https://accounts.example.test/',
        subject: 'upstream-subject',
        refresh_token: 'sealed-refresh-placeholder',
      },
    ],
  });
  const parsed = parseLocalIdentityRecord(config, valid, 'a'.repeat(64));
  assert.equal(parsed.disabled, true);
  assert.equal(parsed.mfa_required, true);
  assert.equal(parsed.totp[0].algorithm, 'SHA256');
  assert.equal(parsed.totp[0].secret, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.equal(parsed.totp[0].label.length, 128);
  assert.equal(parsed.backup_codes[0].id, 'RECOVERY');
  assert.equal(parsed.upstreams[0].id, 'upstream-1');
  assert.equal(parsed.upstreams[0].issuer, 'https://accounts.example.test/');
  assert.deepEqual(parsed.claims, { name: 'Jamie Taylor' });

  const invalid = [
    null,
    [],
    { ...document(), v: 2 },
    { ...document(), unexpected: true },
    { ...document(), id: '/' },
    { ...document(), id: 123 },
    { ...document(), revision: 0 },
    { ...document(), security_version: -1 },
    { ...document(), password: 'plain' },
    { ...document(), password: PHC.replace('m=65536,t=3,p=1', 'm=8192,t=1,p=1') },
    { ...document(), disabled: 'yes' },
    { ...document(), mfa_required: 'yes' },
    { ...document(), mfa_required: 'yes' },
    { ...document(), totp: null },
    { ...document(), totp: {} },
    { ...document(), totp: Array(6).fill(valid.totp[0]) },
    { ...document(), backup_codes: null },
    { ...document(), backup_codes: {} },
    { ...document(), backup_codes: Array(21).fill(valid.backup_codes[0]) },
    { ...document(), upstreams: null },
    { ...document(), upstreams: {} },
    { ...document(), upstreams: Array(21).fill(valid.upstreams[0]) },
    { ...document(), totp: [null] },
    { ...document(), totp: [{ ...valid.totp[0], unexpected: true }] },
    { ...document(), totp: [{ ...valid.totp[0], id: 123 }] },
    { ...document(), totp: [{ ...valid.totp[0], label: null }] },
    { ...document(), totp: [{ ...valid.totp[0], algorithm: null }] },
    { ...document(), totp: [{ ...valid.totp[0], digits: null }] },
    { ...document(), totp: [{ ...valid.totp[0], period: null }] },
    { ...document(), totp: [{ ...valid.totp[0], algorithm: 'MD5' }] },
    { ...document(), totp: [{ ...valid.totp[0], digits: 7 }] },
    { ...document(), totp: [{ ...valid.totp[0], period: 2 }] },
    { ...document(), totp: [{ ...valid.totp[0], secret: 'short' }] },
    { ...document(), totp: [{ ...valid.totp[0], secret: 'k1.local-identity-totp/sealed.payload' }] },
    { ...document(), totp: [{ ...valid.totp[0], secret: '' }] },
    { ...document(), totp: [{ ...valid.totp[0], secret: 123 }] },
    { ...document(), totp: [{ ...valid.totp[0], secret: 'A'.repeat(257) }] },
    { ...document(), totp: [{ ...valid.totp[0], last_used_step: -1 }] },
    { ...document(), backup_codes: [null] },
    { ...document(), backup_codes: [{ ...valid.backup_codes[0], unexpected: true }] },
    { ...document(), backup_codes: [{ ...valid.backup_codes[0], id: 123 }] },
    { ...document(), backup_codes: [{ id: 'bad/id', hash: PHC }] },
    { ...document(), backup_codes: [{ id: 'ok', hash: 'plain' }] },
    {
      ...document(),
      backup_codes: [{ id: 'ok', hash: PHC.replace('m=65536,t=3,p=1', 'm=8192,t=1,p=1') }],
    },
    { ...document(), mfa_required: false, backup_codes: [valid.backup_codes[0]] },
    {
      ...document(),
      mfa_required: false,
      backup_codes: [valid.backup_codes[0]],
    },
    { ...document(), upstreams: [null] },
    { ...document(), upstreams: [{ ...valid.upstreams[0], unexpected: true }] },
    { ...document(), upstreams: [{ ...valid.upstreams[0], id: null }] },
    { ...document(), upstreams: [{ ...valid.upstreams[0], upstream: 123 }] },
    { ...document(), upstreams: [{ ...valid.upstreams[0], issuer: 123 }] },
    { ...document(), upstreams: [{ ...valid.upstreams[0], subject: 123 }] },
    { ...document(), upstreams: [{ ...valid.upstreams[0], refresh_token: {} }] },
    { ...document(), upstreams: [{ upstream: '', issuer: 'https://issuer.test', subject: 'sub' }] },
    { ...document(), upstreams: [{ upstream: 'google:test', issuer: 'not-a-url', subject: 'sub' }] },
    { ...document(), upstreams: [{ upstream: 'google:test', issuer: ' https://issuer.test', subject: 'sub' }] },
    { ...document(), upstreams: [{ upstream: 'google:test', issuer: 'ftp://issuer.test', subject: 'sub' }] },
    { ...document(), upstreams: [{ upstream: 'google:test', issuer: 'https://user@issuer.test', subject: 'sub' }] },
    { ...document(), upstreams: [{ upstream: 'google:test', issuer: 'https://issuer.test?query=yes', subject: 'sub' }] },
    { ...document(), upstreams: [{ upstream: 'google:test', issuer: 'https://issuer.test#fragment', subject: 'sub' }] },
    { ...document(), upstreams: [{ upstream: 'google:test', issuer: 'https://issuer.test', subject: 'sub', id: '/' }] },
    { ...document(), totp: [valid.totp[0], valid.totp[0]] },
    {
      ...document(),
      totp: [valid.totp[0], { ...valid.totp[0], id: 'same-seed', secret: parsed.totp[0].secret }],
    },
    { ...document(), backup_codes: [valid.backup_codes[0], valid.backup_codes[0]] },
    {
      ...document(),
      upstreams: [
        { ...valid.upstreams[0], id: 'duplicate' },
        { ...valid.upstreams[0], id: 'duplicate' },
      ],
    },
    { ...document(), claims: null },
    { ...document(), claims: [] },
    { ...document(), claims: { unexpected: 'claim' } },
    { ...document(), claims: { name: 42 } },
    { ...document(), claims: { name: '' } },
    { ...document(), claims: { name: 'x'.repeat(513) } },
    { ...document(), claims: { picture: 'http://images.example.test/avatar.png' } },
  ];
  for (const candidate of invalid) assert.equal(parseLocalIdentityRecord(config, candidate, 'key'), undefined);
});

test('the local service equalises missing and malformed password verification', async () => {
  const config = configWith({ LOCAL_PASSWORD_MAX_BYTES: '64' });
  const key = await localIdentityKey(config, EMAIL);
  const calls = [];
  let throwOnce = true;
  const binding = memoryBinding(new Map([[key, document()]]), async (hash, password) => {
    calls.push({ hash, password });
    if (throwOnce) {
      throwOnce = false;
      throw new Error('malformed PHC');
    }
    return password === 'correct';
  });
  const store = createLocalIdentityStore(config, { SAG_LOCAL_IDENTITIES: binding });
  assert.equal(createLocalIdentityStore(configWith({ LOCAL_IDENTITIES_BACKEND: 'none' }), {}), undefined);
  assert.throws(() => createLocalIdentityStore(config, {}), /requires the Node adapter binding/);

  const found = await store.find(EMAIL);
  assert.equal(found.malformed, false);
  assert.equal(await store.verifyPassword(found, 'correct'), true);
  assert.equal(calls.length, 2, 'a verifier failure falls back to the public dummy verifier');

  const absent = await store.find('absent@example.test');
  assert.equal(absent.record, undefined);
  assert.equal(absent.malformed, false);
  assert.equal(await store.verifyPassword(absent, 'correct'), false);

  binding.records.set(key, { malformed: true });
  const malformed = await store.find(EMAIL);
  assert.equal(malformed.malformed, true);
  assert.equal(await store.verifyPassword(malformed, 'correct'), false);
  assert.equal(await store.verifyPassword(found, 'x'.repeat(65)), false);
  assert.equal(calls.at(-1).password, 'password-too-long');

  const unreadableStore = createLocalIdentityStore(config, {
    SAG_LOCAL_IDENTITIES: {
      ...binding,
      get: async () => {
        throw new Error('permission refused');
      },
    },
  });
  const unreadable = await unreadableStore.find(EMAIL);
  assert.equal(unreadable.malformed, true);
  assert.match(unreadable.error.message, /permission refused/);
});

test('backup codes are one-use compare-and-swap credentials', async () => {
  const config = configWith({ PROFILE_CLAIMS: 'name' });
  const key = await localIdentityKey(config, EMAIL);
  const code = 'RECOVERY-ABCD-EFGH';
  const binding = memoryBinding(
    new Map([[
      key,
      document({
        claims: { name: 'Jamie Taylor', locale: 'en-GB' },
        backup_codes: [{ id: 'recovery', hash: PHC }],
      }),
    ]]),
    async (_hash, password) => password === code,
  );
  const store = createLocalIdentityStore(config, { SAG_LOCAL_IDENTITIES: binding });
  const found = await store.find(EMAIL);
  assert.deepEqual(store.profileClaims(found.record), { name: 'Jamie Taylor' });
  assert.equal(store.requiresSecondFactor(found.record), true);
  assert.equal(await store.verifySecondFactor(found.record, 'RECOVERY-WRONG'), undefined);
  assert.equal(await store.verifySecondFactor(found.record, 'not a selector'), undefined);

  const refused = await store.verifySecondFactor(
    found.record,
    'recovery -abcd-efgh',
    Date.now(),
    { consume: false },
  );
  assert.equal(refused.method, 'recovery');
  assert.equal(binding.records.get(key).backup_codes.length, 1);

  const result = await store.verifySecondFactor(found.record, 'recovery -abcd-efgh');
  assert.equal(result.method, 'recovery');
  assert.equal(result.record.revision, 2);
  assert.deepEqual(result.record.backup_codes, []);
  assert.equal(result.record.mfa_required, true, 'using the final recovery code must not downgrade MFA policy');
  assert.equal(store.requiresSecondFactor(result.record), true);
  assert.equal(
    store.requiresSecondFactor(result.record),
    true,
    'using the last recovery code must not silently downgrade later sign-ins to password-only',
  );
  assert.equal(binding.records.get(key).mfa_required, true);
  assert.deepEqual(
    binding.records.get(key).claims,
    { name: 'Jamie Taylor', locale: 'en-GB' },
    'state-only credential updates preserve valid claims hidden by this deployment',
  );

  const losingBinding = { ...binding, replace: async () => false };
  const losingStore = createLocalIdentityStore(config, { SAG_LOCAL_IDENTITIES: losingBinding });
  assert.equal(await losingStore.verifySecondFactor(found.record, code), undefined);

  const brokenVerifier = createLocalIdentityStore(config, {
    SAG_LOCAL_IDENTITIES: {
      ...binding,
      verifyArgon2id: async () => {
        throw new Error('malformed backup verifier');
      },
    },
  });
  assert.equal(await brokenVerifier.verifySecondFactor(found.record, code), undefined);
});

test('plaintext TOTP needs no sealing key and retains replay protection and conditional writes', async () => {
  const config = { ...configWith(), secrets: [] };
  const key = await localIdentityKey(config, EMAIL);
  const secret = encodeBase32(new TextEncoder().encode('12345678901234567890'));
  const now = 59_000;
  const code = await totpForStep(secret, 1, { digits: 8 });
  const binding = memoryBinding(
    new Map([
      [
        key,
        document({
          totp: [
            { id: 'other', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
            { id: 'primary', secret, algorithm: 'SHA1', digits: 8, period: 30 },
          ],
        }),
      ],
    ]),
  );
  const store = createLocalIdentityStore(config, { SAG_LOCAL_IDENTITIES: binding });
  const found = await store.find(EMAIL);
  assert.equal(await store.verifySecondFactor(found.record, '00000000', now), undefined);
  const refused = await store.verifySecondFactor(found.record, code, now, { consume: false });
  assert.equal(refused.method, 'totp');
  assert.equal(binding.records.get(key).revision, 1);
  assert.equal(binding.records.get(key).totp[1].last_used_step, undefined);
  const result = await store.verifySecondFactor(found.record, code, now);
  assert.equal(result.method, 'totp');
  assert.equal(result.record.totp[1].last_used_step, 1);
  assert.equal(result.record.totp[1].secret, secret);
  assert.equal(await store.verifySecondFactor(result.record, code, now), undefined, 'the same time-step is one use');

  const losing = createLocalIdentityStore(config, {
    SAG_LOCAL_IDENTITIES: { ...binding, replace: async () => false },
  });
  const nextCode = await totpForStep(secret, 2, { digits: 8 });
  assert.equal(await losing.verifySecondFactor(result.record, nextCode, 89_000), undefined);
});

test('session checks support record keys and legacy address lookup', async () => {
  const config = configWith();
  const key = await localIdentityKey(config, EMAIL);
  const binding = memoryBinding(new Map([[key, document()]]));
  const store = createLocalIdentityStore(config, { SAG_LOCAL_IDENTITIES: binding });
  assert.equal(await store.validateSession({}), true);
  assert.equal(
    await store.validateSession({
      localIdentityId: RECORD_ID,
      localIdentityKey: key,
      localSecurityVersion: 1,
    }),
    true,
  );
  assert.equal(
    await store.validateSession({
      email: EMAIL,
      localIdentityId: RECORD_ID,
      localSecurityVersion: 1,
    }),
    true,
  );
  assert.equal(
    await store.validateSession({
      localIdentityId: RECORD_ID,
      localIdentityKey: key,
      localSecurityVersion: 2,
    }),
    false,
  );
  binding.records.set(key, document({ disabled: true }));
  assert.equal(
    await store.validateSession({
      localIdentityId: RECORD_ID,
      localIdentityKey: key,
      localSecurityVersion: 1,
    }),
    false,
  );
});

test('refresh credentials can be rekeyed without changing plaintext TOTP', async () => {
  const oldConfig = configWith({ SAG_SECRET: PREVIOUS_SECRET });
  const rotated = configWith({ SAG_SECRET_PREVIOUS: PREVIOUS_SECRET });
  const key = await localIdentityKey(rotated, EMAIL);
  const secret = encodeBase32(new TextEncoder().encode('12345678901234567890'));
  const link = {
    id: 'work',
    upstream: 'google:example-test',
    issuer: 'https://accounts.example.test',
    subject: 'upstream-subject',
  };
  const oldRefresh = await sealUpstreamRefreshToken(oldConfig, RECORD_ID, link, 'refresh-value');
  const raw = document({
    totp: [{ id: 'primary', secret, algorithm: 'SHA1', digits: 6, period: 30, last_used_step: 4 }],
    upstreams: [
      { ...link, refresh_token: oldRefresh },
      { id: 'without-token', upstream: 'google:other', issuer: 'https://other.example.test', subject: 'sub' },
    ],
  });
  const binding = memoryBinding(new Map([[key, raw]]));
  const store = createLocalIdentityStore(rotated, { SAG_LOCAL_IDENTITIES: binding });
  const record = (await store.find(EMAIL)).record;
  const changed = await store.rekeyRecord(record);
  assert.equal(changed.changed, true);
  assert.equal(changed.record.revision, 2);
  assert.deepEqual(changed.record.totp, record.totp);
  assert.notEqual(changed.record.upstreams[0].refresh_token, oldRefresh);

  const unchanged = await store.rekeyRecord(changed.record);
  assert.equal(unchanged.changed, false);
  assert.equal(unchanged.record, changed.record);

  const wrongRefresh = await seal(
    rotated.secrets[0],
    'local-identity-refresh/' + RECORD_ID + '/' + link.id,
    {
      v: 1,
      identity_id: 'another-record',
      link_id: link.id,
      upstream: link.upstream,
      issuer: link.issuer,
      subject: link.subject,
      token: 'refresh-value',
    },
  );
  const wronglyBound = parseLocalIdentityRecord(
    rotated,
    document({ upstreams: [{ ...link, refresh_token: wrongRefresh }] }),
    key,
  );
  await assert.rejects(() => store.rekeyRecord(wronglyBound), /bound to a different identity/);

  const losingStore = createLocalIdentityStore(rotated, {
    SAG_LOCAL_IDENTITIES: { ...binding, replace: async () => false },
  });
  await assert.rejects(() => losingStore.rekeyRecord(record), /changed while it was being rekeyed/);

  await assert.rejects(
    () => createLocalIdentityStore(rotated, { SAG_LOCAL_IDENTITIES: { ...binding, list: undefined } }).rekeyAll(),
    /cannot list records/,
  );
});

test('bulk rekey counts changed records and rejects malformed input', async () => {
  const oldConfig = configWith({ SAG_SECRET: PREVIOUS_SECRET });
  const rotated = configWith({ SAG_SECRET_PREVIOUS: PREVIOUS_SECRET });
  const secret = encodeBase32(new TextEncoder().encode('12345678901234567890'));
  const link = { id: 'work', upstream: 'google:test', issuer: 'https://issuer.test', subject: 'sub' };
  const oldCiphertext = await sealUpstreamRefreshToken(oldConfig, RECORD_ID, link, 'refresh-value');
  const currentCiphertext = await sealUpstreamRefreshToken(rotated, 'second-record', link, 'refresh-value');
  const firstKey = 'a'.repeat(64);
  const secondKey = 'b'.repeat(64);
  const binding = memoryBinding(
    new Map([
      [firstKey, document({ upstreams: [{ ...link, refresh_token: oldCiphertext }] })],
      [
        secondKey,
        document({
          id: 'second-record',
          totp: [{ id: 'primary', secret, algorithm: 'SHA1', digits: 6, period: 30 }],
          upstreams: [{ ...link, refresh_token: currentCiphertext }],
        }),
      ],
    ]),
  );
  const store = createLocalIdentityStore(rotated, { SAG_LOCAL_IDENTITIES: binding });
  assert.deepEqual(await store.rekeyAll(), { changed: 1, unchanged: 1 });

  binding.records.set('c'.repeat(64), { broken: true });
  await assert.rejects(() => store.rekeyAll(), /is malformed/);
});

test('provisioning identifiers are opaque and within the record grammar', () => {
  const identity = newLocalIdentityId();
  const credential = newCredentialId();
  assert.match(identity, /^[A-Za-z0-9_-]+$/);
  assert.match(credential, /^[A-Za-z0-9_-]+$/);
  assert.notEqual(identity, newLocalIdentityId());
  assert.notEqual(credential, newCredentialId());
});
