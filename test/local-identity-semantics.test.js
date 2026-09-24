// Security semantics shared by local password authentication and an upstream
// identity explicitly linked to the same operator-provisioned record.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ACR, AMR, acrForLocal, satisfies } from '../src/acr.js';
import { loadConfig, assertUsable, ConfigError } from '../src/config.js';
import { clearJwksCache, decodeJwt } from '../src/crypto/jose.js';
import { seal } from '../src/crypto/secrets.js';
import { handleUserinfo } from '../src/endpoints/userinfo.js';
import { subjectFor, subjectForLocalIdentity } from '../src/identity.js';
import {
  createLocalIdentityStore,
  localIdentityAllowed,
  localIdentityKey,
} from '../src/local-identities/index.js';
import { issueCode, redeemCode } from '../src/oauth/code.js';
import { idTokenClaims, issueAccessToken, readAccessToken } from '../src/oauth/tokens.js';
import {
  cookieNameFor,
  newSession,
  readSessionByName,
  reauthenticate,
  sealSession,
} from '../src/session.js';
import { checkLocalAuthAllowed } from '../src/store/limits.js';
import { nowSeconds } from '../src/util/bytes.js';
import { clearUpstreamMetadataCache } from '../src/upstream/index.js';
import {
  createInstance,
  authorizeUrl,
  extractField,
  pkce,
  redeem,
  DEV_CLIENT,
  DEV_REDIRECT,
} from './harness.js';
import { createStubProvider, readUpstreamRedirect } from './upstream-stub.js';

const ISSUER = 'http://localhost:8787';
const SECRET = 'test-secret-'.repeat(4);
const SUBJECT_SALT = 'local-subject-salt-'.repeat(2);
const EMAIL = 'jamie.taylor@example.test';
const TAGGED_EMAIL = 'jamie.taylor+local@example.test';
const IDENTITY_ID = 'account_xjH8f3sM';
const PASSWORD_PHC =
  '$argon2id$v=19$m=65536,t=3,p=1$c2FnLWxvY2FsLWR1bW15MQ$KffQgtYBtmwZAFnvnsXZ7vL8/HU8Mz58bkyIR3r/krU';
const BACKUP_PHC =
  '$argon2id$v=19$m=65536,t=3,p=1$+e9zT46OJ4wZS3eDU9SVXg$3FRCKq9jkqDyLJEMOdCRfhw7DgVEGZwYHfMEFlgbiJY';

const configWith = (overrides = {}) =>
  loadConfig({
    SAG_ISSUER: ISSUER,
    SAG_SECRET: SECRET,
    SUBJECT_SALT,
    ...overrides,
  });

function localConfig(overrides = {}) {
  return configWith({
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
    STATE_STORE_BACKEND: 'memory',
    ...overrides,
  });
}

function transaction(scope = ['openid', 'email']) {
  return {
    client_id: 'local-client',
    redirect_uri: 'https://app.example.test/callback',
    scope,
  };
}

async function roundTripGrant(config, session, scope = ['openid', 'email']) {
  const tx = transaction(scope);
  const sub = await subjectForLocalIdentity(config, IDENTITY_ID, {
    clientId: tx.client_id,
  });
  const code = await issueCode(config, { tx, session, sub, email: EMAIL });
  return redeemCode(config, {
    code,
    clientId: tx.client_id,
    redirectUri: tx.redirect_uri,
  });
}

async function userinfo(config, accessToken) {
  const response = await handleUserinfo({
    config,
    request: new Request(ISSUER + '/userinfo', {
      headers: { authorization: 'Bearer ' + accessToken },
    }),
    absolute: (path) => ISSUER + path,
  });
  assert.equal(response.status, 200);
  return response.json();
}

function storedIdentity(overrides = {}) {
  return {
    v: 1,
    id: IDENTITY_ID,
    revision: 1,
    security_version: 3,
    password: PASSWORD_PHC,
    totp: [],
    backup_codes: [],
    upstreams: [],
    ...overrides,
  };
}

async function exchangeLocalCode(record, { authenticationEmail = EMAIL, publicEmail = EMAIL } = {}) {
  let expectedKey;
  const binding = {
    get: async (key) => (key === expectedKey ? record : undefined),
    replace: async () => false,
    verifyArgon2id: async () => false,
  };
  const sag = createInstance({
    SUBJECT_SALT,
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
    STATE_STORE_BACKEND: 'memory',
    SAG_LOCAL_IDENTITIES: binding,
  });
  const config = loadConfig(sag.env);
  expectedKey = await localIdentityKey(config, authenticationEmail);
  const session = newSession(config, {
    email: authenticationEmail,
    acr: ACR.LOCAL_PASSWORD,
    amr: [AMR.PASSWORD],
    localIdentityId: IDENTITY_ID,
    localIdentityKey: expectedKey,
    localSecurityVersion: 3,
  });
  const code = await issueCode(config, {
    tx: {
      client_id: DEV_CLIENT,
      redirect_uri: DEV_REDIRECT,
      scope: ['openid', 'email'],
    },
    session,
    sub: await subjectForLocalIdentity(config, IDENTITY_ID, { clientId: DEV_CLIENT }),
    email: publicEmail,
  });
  const response = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: DEV_CLIENT,
      redirect_uri: DEV_REDIRECT,
    }).toString(),
  });
  return { response, body: await response.json() };
}

function localAuthenticationInstance({ secondFactor = false, upstream = false } = {}) {
  let record = storedIdentity({
    backup_codes: secondFactor ? [{ id: 'RECOVERY', hash: BACKUP_PHC }] : [],
  });
  return createInstance({
    SUBJECT_SALT,
    OTP_ENABLED: 'false',
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
    STATE_STORE_BACKEND: 'memory',
    ...(upstream
      ? {
          UPSTREAM_OIDC_LOCAL_CLIENT_ID: 'example.test:upstream-client',
          UPSTREAM_OIDC_LOCAL_CLIENT_SECRET: 'upstream-secret',
          UPSTREAM_OIDC_LOCAL_ISSUER: 'https://accounts.example.test',
        }
      : {}),
    SAG_LOCAL_IDENTITIES: {
      get: async () => record,
      replace: async (_key, revision, next) => {
        if (record.revision !== revision) return false;
        record = next;
        return true;
      },
      verifyArgon2id: async (hash, password) =>
        hash === BACKUP_PHC
          ? password === 'RECOVERY-ABCD-EFGH'
          : password === 'correct horse battery staple',
    },
  });
}

async function submitLocalPassword(instance, { acr, password, authorize = {} }) {
  const { verifier, challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, acr_values: acr, ...authorize });
  const first = await instance.raw(path);
  const emailTx = extractField(await first.text());
  assert.ok(emailTx);
  const passwordPage = await instance.postForm('/authorize/email', { tx: emailTx, email: EMAIL });
  assert.equal(passwordPage.status, 200);
  const passwordTx = extractField(await passwordPage.text());
  assert.ok(passwordTx);
  const response = await instance.postForm('/authorize/local-password', { tx: passwordTx, password });
  return { response, body: await response.text(), verifier };
}

test('local ACRs remain separate from email and federated authentication families', () => {
  assert.deepEqual(acrForLocal(), {
    acr: ACR.LOCAL_PASSWORD,
    amr: [AMR.PASSWORD],
  });
  assert.deepEqual(acrForLocal('totp'), {
    acr: ACR.LOCAL_MFA,
    amr: [AMR.PASSWORD, AMR.OTP, AMR.MFA],
  });
  assert.deepEqual(acrForLocal('recovery'), {
    acr: ACR.LOCAL_MFA,
    amr: [AMR.PASSWORD, AMR.RECOVERY, AMR.MFA],
  });

  assert.equal(satisfies(ACR.LOCAL_PASSWORD, [ACR.LOCAL_PASSWORD]), true);
  assert.equal(satisfies(ACR.LOCAL_PASSWORD, [ACR.LOCAL_MFA]), false);
  assert.equal(satisfies(ACR.LOCAL_MFA, [ACR.LOCAL_PASSWORD]), true);
  assert.equal(satisfies(ACR.LOCAL_MFA, [ACR.LOCAL_MFA]), true);

  for (const nonLocal of [ACR.OTP, ACR.FEDERATED, ACR.FEDERATED_MFA]) {
    assert.equal(satisfies(ACR.LOCAL_MFA, [nonLocal]), false, 'local MFA must not satisfy ' + nonLocal);
    assert.equal(satisfies(nonLocal, [ACR.LOCAL_PASSWORD]), false, nonLocal + ' must not satisfy local password');
    assert.equal(satisfies(nonLocal, [ACR.LOCAL_MFA]), false, nonLocal + ' must not satisfy local MFA');
  }

  assert.equal(
    satisfies(ACR.FEDERATED, [ACR.LOCAL_PASSWORD, ACR.FEDERATED]),
    true,
    'acr_values alternatives retain their normal OR semantics',
  );
});

test('an incompatible ACR request cannot turn the local flow into a password-confirmation oracle', async () => {
  for (const secondFactor of [false, true]) {
    const instance = localAuthenticationInstance({ secondFactor });
    const wrong = await submitLocalPassword(instance, {
      acr: ACR.FEDERATED,
      password: 'wrong password',
    });
    const correct = await submitLocalPassword(instance, {
      acr: ACR.FEDERATED,
      password: 'correct horse battery staple',
    });

    assert.equal(correct.response.status, wrong.response.status);
    assert.equal(correct.response.status, 400);
    assert.match(wrong.body, /We could not sign you in/);
    assert.match(correct.body, /We could not sign you in/);
    assert.match(correct.body, /name="password"/);
    assert.doesNotMatch(correct.body, /one-time code/i, 'MFA availability must not be disclosed either');
  }

  for (const acr of [ACR.LOCAL_MFA, ACR.MFA]) {
    const passwordOnly = localAuthenticationInstance();
    const impossibleStepUp = await submitLocalPassword(passwordOnly, {
      acr,
      password: 'correct horse battery staple',
    });
    assert.equal(impossibleStepUp.response.status, 400);
    assert.match(impossibleStepUp.body, /We could not sign you in/);
    assert.match(impossibleStepUp.body, /name="password"/);
  }
});

test('local password and a recovery code satisfy generic MFA while retaining the local acr', async () => {
  const sag = localAuthenticationInstance({ secondFactor: true });
  const first = await submitLocalPassword(sag, {
    acr: ACR.MFA,
    password: 'correct horse battery staple',
  });
  assert.equal(first.response.status, 200);
  assert.match(first.body, /Verification code/);

  const completed = await sag.postForm('/authorize/local-mfa', {
    tx: extractField(first.body),
    code: 'RECOVERY-ABCD-EFGH',
  });
  assert.equal(completed.status, 303);
  const tokens = await redeem(sag, {
    authCode: new URL(completed.headers.get('location')).searchParams.get('code'),
    verifier: first.verifier,
  });
  assert.equal(tokens.res.status, 200);
  const claims = decodeJwt(tokens.body.id_token).payload;
  assert.equal(claims.acr, ACR.LOCAL_MFA);
  assert.deepEqual(claims.amr, [AMR.PASSWORD, AMR.RECOVERY, AMR.MFA]);
  assert.equal(Object.hasOwn(claims, 'email_verified'), false);

  const { challenge } = await pkce();
  const silent = await sag.raw(authorizeUrl({ challenge, acr_values: ACR.MFA, prompt: 'none' }).path);
  assert.equal(silent.status, 303);
  const location = new URL(silent.headers.get('location'));
  assert.ok(location.searchParams.get('code'));
  assert.equal(location.searchParams.has('error'), false);
});

test('password-only and recovery-code local sign-ins complete with unverified email', async () => {
  const passwordOnly = localAuthenticationInstance();
  const password = await submitLocalPassword(passwordOnly, {
    acr: ACR.LOCAL_PASSWORD,
    password: 'correct horse battery staple',
  });
  assert.equal(password.response.status, 303);
  const passwordCode = new URL(password.response.headers.get('location')).searchParams.get('code');
  const passwordTokens = await redeem(passwordOnly, {
    authCode: passwordCode,
    verifier: password.verifier,
  });
  assert.equal(passwordTokens.res.status, 200, JSON.stringify(passwordTokens.body));
  const passwordClaims = decodeJwt(passwordTokens.body.id_token).payload;
  assert.equal(passwordClaims.acr, ACR.LOCAL_PASSWORD);
  assert.deepEqual(passwordClaims.amr, [AMR.PASSWORD]);
  assert.equal(Object.hasOwn(passwordClaims, 'email_verified'), false);

  const reauthenticated = await submitLocalPassword(passwordOnly, {
    acr: ACR.LOCAL_PASSWORD,
    password: 'correct horse battery staple',
    authorize: { prompt: 'login' },
  });
  assert.equal(reauthenticated.response.status, 303);

  const withRecovery = localAuthenticationInstance({ secondFactor: true });
  const firstFactor = await submitLocalPassword(withRecovery, {
    acr: ACR.LOCAL_MFA,
    password: 'correct horse battery staple',
  });
  assert.equal(firstFactor.response.status, 200);
  assert.match(firstFactor.body, /Verification code/);
  let mfaTx = extractField(firstFactor.body);
  assert.ok(mfaTx);

  const wrong = await withRecovery.postForm('/authorize/local-mfa', {
    tx: mfaTx,
    code: 'RECOVERY-WRONG',
  });
  assert.equal(wrong.status, 400);
  const wrongBody = await wrong.text();
  assert.match(wrongBody, /We could not sign you in/);
  mfaTx = extractField(wrongBody);

  const completed = await withRecovery.postForm('/authorize/local-mfa', {
    tx: mfaTx,
    code: 'RECOVERY-ABCD-EFGH',
  });
  assert.equal(completed.status, 303);
  const mfaCode = new URL(completed.headers.get('location')).searchParams.get('code');
  const mfaTokens = await redeem(withRecovery, {
    authCode: mfaCode,
    verifier: firstFactor.verifier,
  });
  assert.equal(mfaTokens.res.status, 200, JSON.stringify(mfaTokens.body));
  const mfaClaims = decodeJwt(mfaTokens.body.id_token).payload;
  assert.equal(mfaClaims.acr, ACR.LOCAL_MFA);
  assert.deepEqual(mfaClaims.amr, [AMR.PASSWORD, AMR.RECOVERY, AMR.MFA]);
  assert.equal(Object.hasOwn(mfaClaims, 'email_verified'), false);

  const exhausted = await submitLocalPassword(withRecovery, {
    acr: ACR.LOCAL_MFA,
    password: 'correct horse battery staple',
    authorize: { prompt: 'login' },
  });
  assert.equal(exhausted.response.status, 200);
  assert.match(
    exhausted.body,
    /Verification code/,
    'using the last recovery code leaves the account MFA-locked rather than password-only',
  );
});

test('malformed records, exhausted limits and invalid local stages stay on generic responses', async () => {
  const passwordInstance = createInstance({
    SUBJECT_SALT,
    OTP_ENABLED: 'false',
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
    STATE_STORE_BACKEND: 'memory',
    LOCAL_AUTH_MAX_ATTEMPTS: '1',
    SAG_LOCAL_IDENTITIES: {
      get: async () => { throw new Error('record is unreadable'); },
      replace: async () => false,
      verifyArgon2id: async () => false,
    },
  });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const refused = await submitLocalPassword(passwordInstance, {
      acr: ACR.LOCAL_PASSWORD,
      password: 'wrong password',
    });
    assert.equal(refused.response.status, 400);
    assert.match(refused.body, /We could not sign you in/);
  }

  let mfaRecord = storedIdentity({
    backup_codes: [{ id: 'RECOVERY', hash: BACKUP_PHC }],
  });
  let unreadable = false;
  const mfaInstance = createInstance({
    SUBJECT_SALT,
    OTP_ENABLED: 'false',
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
    STATE_STORE_BACKEND: 'memory',
    LOCAL_AUTH_MAX_ATTEMPTS: '1',
    SAG_LOCAL_IDENTITIES: {
      get: async () => {
        if (unreadable) throw new Error('record disappeared');
        return mfaRecord;
      },
      replace: async (_key, revision, next) => {
        if (mfaRecord.revision !== revision) return false;
        mfaRecord = next;
        return true;
      },
      verifyArgon2id: async (hash, password) =>
        hash === BACKUP_PHC
          ? password === 'RECOVERY-ABCD-EFGH'
          : password === 'correct horse battery staple',
    },
  });
  const firstFactor = await submitLocalPassword(mfaInstance, {
    acr: ACR.LOCAL_MFA,
    password: 'correct horse battery staple',
  });
  assert.equal(firstFactor.response.status, 200);
  let tx = extractField(firstFactor.body);
  unreadable = true;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const refused = await mfaInstance.postForm('/authorize/local-mfa', { tx, code: 'RECOVERY-WRONG' });
    assert.equal(refused.status, 400);
    const body = await refused.text();
    assert.match(body, /We could not sign you in/);
    tx = extractField(body);
  }

  const { challenge } = await pkce();
  const first = await mfaInstance.raw(authorizeUrl({ challenge }).path);
  const emailStage = extractField(await first.text());
  const wrongPasswordStage = await mfaInstance.postForm('/authorize/local-password', {
    tx: emailStage,
    password: 'anything',
  });
  assert.equal(wrongPasswordStage.status, 400);
  const wrongMfaStage = await mfaInstance.postForm('/authorize/local-mfa', {
    tx: emailStage,
    code: 'anything',
  });
  assert.equal(wrongMfaStage.status, 400);
});

test('a planted local session is unusable when no authoritative local store exists', async () => {
  const instance = createInstance({ SUBJECT_SALT });
  const config = loadConfig(instance.env);
  const session = newSession(config, {
    email: EMAIL,
    acr: ACR.LOCAL_PASSWORD,
    amr: [AMR.PASSWORD],
    localIdentityId: IDENTITY_ID,
    localIdentityKey: 'a'.repeat(64),
    localSecurityVersion: 1,
  });
  const cookieName = await cookieNameFor(config);
  instance.cookies.set(cookieName, encodeURIComponent(await sealSession(config, session)));
  const { challenge } = await pkce();
  const response = await instance.raw(authorizeUrl({ challenge, prompt: 'none' }).path);
  assert.equal(response.status, 303);
  assert.equal(new URL(response.headers.get('location')).searchParams.get('error'), 'login_required');
});

test('local discovery and password alternatives describe what the instance can actually do', async () => {
  const local = localAuthenticationInstance();
  const metadata = await local.json('/.well-known/openid-configuration');
  assert.equal(metadata.res.status, 200);
  assert.ok(metadata.body.acr_values_supported.includes(ACR.LOCAL_PASSWORD));
  assert.ok(metadata.body.acr_values_supported.includes(ACR.LOCAL_MFA));
  assert.ok(metadata.body.acr_values_supported.includes(ACR.MFA));
  assert.ok(metadata.body.claims_supported.includes('name'));

  const withUpstream = localAuthenticationInstance({ upstream: true });
  const { challenge } = await pkce();
  const first = await withUpstream.raw(authorizeUrl({ challenge }).path);
  const emailTx = extractField(await first.text());
  const passwordPage = await withUpstream.postForm('/authorize/email', { tx: emailTx, email: EMAIL });
  const body = await passwordPage.text();
  assert.match(body, /Continue with/);
  assert.match(body, /name="upstream"/);
});

test('local attempt limits include an unforgeable network bucket and fail closed', async () => {
  const config = localConfig({
    LOCAL_AUTH_MAX_ATTEMPTS: '2',
    LOCAL_AUTH_NETWORK_MAX_ATTEMPTS: '1',
  });
  const counts = new Map();
  const errors = [];
  const ctx = {
    config,
    request: new Request(ISSUER + '/authorize/local-password', {
      headers: { 'x-sag-client-ip': '192.0.2.10' },
    }),
    stateStore: {
      increment: async (key) => {
        const count = (counts.get(key) || 0) + 1;
        counts.set(key, count);
        return count;
      },
    },
    log: { error: (message, fields) => errors.push({ message, fields }) },
  };
  assert.deepEqual(await checkLocalAuthAllowed(ctx, EMAIL), {
    allowed: true,
    enforced: true,
    reason: undefined,
  });
  assert.deepEqual(await checkLocalAuthAllowed(ctx, EMAIL), {
    allowed: false,
    enforced: true,
    reason: 'limit',
  });
  assert.equal(
    [...counts.entries()].find(([key]) => key.includes(':address:'))[1],
    1,
    'a denied network must not allocate or advance arbitrary address counters',
  );

  const addressOnly = new Map();
  const withoutNetworkBucket = {
    ...ctx,
    config: localConfig({
      LOCAL_AUTH_MAX_ATTEMPTS: '2',
      LOCAL_AUTH_NETWORK_MAX_ATTEMPTS: '0',
    }),
    stateStore: {
      increment: async (key) => {
        addressOnly.set(key, (addressOnly.get(key) || 0) + 1);
        return addressOnly.get(key);
      },
    },
  };
  assert.equal((await checkLocalAuthAllowed(withoutNetworkBucket, EMAIL)).allowed, true);
  assert.ok([...addressOnly.keys()].every((key) => key.includes(':address:')));

  assert.deepEqual(await checkLocalAuthAllowed({ ...ctx, stateStore: undefined }, EMAIL), {
    allowed: false,
    enforced: false,
    reason: 'store',
  });
  const failed = await checkLocalAuthAllowed(
    {
      ...ctx,
      stateStore: { increment: async () => { throw new Error('store unavailable'); } },
    },
    EMAIL,
    'mfa',
  );
  assert.deepEqual(failed, { allowed: false, enforced: false, reason: 'store' });
  assert.match(errors.at(-1).fields.error, /store unavailable/);
});

test('a stable local id joins password and linked-upstream sign-in without trusting the address as the subject', async () => {
  const config = configWith();
  const app = { clientId: 'app' };
  const local = await subjectForLocalIdentity(config, IDENTITY_ID, app);

  assert.equal(
    await subjectForLocalIdentity(config, IDENTITY_ID, app),
    local,
    'password and an exact upstream link both resolve through the same record id',
  );
  assert.notEqual(local, await subjectFor(config, EMAIL, app), 'an unlinked verified-email identity stays distinct');
  assert.notEqual(
    local,
    await subjectForLocalIdentity(config, 'a-different-local-account', app),
    'changing an address must not be modelled by minting the same subject for two local records',
  );

  const rotatedSecret = configWith({ SAG_SECRET: 'rotated-secret-'.repeat(3) });
  assert.equal(
    await subjectForLocalIdentity(rotatedSecret, IDENTITY_ID, app),
    local,
    'rotating the encryption key must not orphan a local account',
  );

  const pairwise = configWith({ SUBJECT_TYPE: 'pairwise' });
  const first = await subjectForLocalIdentity(pairwise, IDENTITY_ID, { clientId: 'first' });
  const second = await subjectForLocalIdentity(pairwise, IDENTITY_ID, { clientId: 'second' });
  assert.notEqual(first, second);
  assert.equal(
    await subjectForLocalIdentity(pairwise, IDENTITY_ID, {
      clientId: 'another-client',
      sectorIdentifier: 'shared-sector',
    }),
    await subjectForLocalIdentity(pairwise, IDENTITY_ID, {
      clientId: 'one-more-client',
      sectorIdentifier: 'shared-sector',
    }),
  );

  await assert.rejects(() => subjectForLocalIdentity(config, '', app), /valid stable identity id/);
  await assert.rejects(() => subjectForLocalIdentity(config, 'contains/slash', app), /valid stable identity id/);
  await assert.rejects(() => subjectForLocalIdentity(config, 'x'.repeat(129), app), /valid stable identity id/);
});

test('an upstream link matches the full trusted triple and seals refresh credentials before storage', async () => {
  const config = localConfig();
  const key = await localIdentityKey(config, EMAIL);
  const document = storedIdentity({
    upstreams: [
      {
        id: 'work-account',
        upstream: 'google:example-test',
        issuer: 'https://accounts.example.test',
        subject: '00u-exact-subject',
      },
    ],
  });
  let written;
  const binding = {
    get: async (candidate) => (candidate === key ? document : undefined),
    replace: async (candidate, revision, next) => {
      assert.equal(candidate, key);
      assert.equal(revision, 1);
      written = next;
      return true;
    },
    verifyArgon2id: async () => false,
  };
  const store = createLocalIdentityStore(config, { SAG_LOCAL_IDENTITIES: binding });
  const exact = await store.linked(EMAIL, {
    upstream: 'google:example-test',
    issuer: 'https://accounts.example.test',
    subject: '00u-exact-subject',
  });
  assert.equal(exact.record.id, IDENTITY_ID);
  assert.equal(exact.link.id, 'work-account');

  for (const mismatch of [
    { upstream: 'microsoft:example-test', issuer: 'https://accounts.example.test', subject: '00u-exact-subject' },
    { upstream: 'google:example-test', issuer: 'https://accounts.example.test/', subject: '00u-exact-subject' },
    { upstream: 'google:example-test', issuer: 'https://other-issuer.example.test', subject: '00u-exact-subject' },
    { upstream: 'google:example-test', issuer: 'https://accounts.example.test', subject: 'different-subject' },
  ]) {
    assert.equal(await store.linked(EMAIL, mismatch), undefined);
  }
  assert.equal(
    await store.linked('someone.else@example.test', {
      upstream: 'google:example-test',
      issuer: 'https://accounts.example.test',
      subject: '00u-exact-subject',
    }),
    undefined,
    'a link on another local account is never found by subject alone',
  );

  const token = 'refresh-token-that-must-not-be-plain-text';
  const updated = await store.storeRefreshToken(exact.record, exact.link, token);
  assert.equal(updated.revision, 2);
  assert.ok(written.upstreams[0].refresh_token);
  assert.doesNotMatch(JSON.stringify(written), new RegExp(token));
});

test('a linked upstream converges subjects, retries refresh persistence and falls back locally', async (t) => {
  clearUpstreamMetadataCache();
  clearJwksCache();
  const stub = await createStubProvider();
  const restore = stub.install();
  t.after(restore);

  let record = storedIdentity({
    upstreams: [
      {
        id: 'work-account',
        upstream: 'oidc/local',
        issuer: stub.issuer,
        subject: 'upstream-subject-1',
      },
    ],
  });
  let writeAttempts = 0;
  let failAllWrites = false;
  const instance = createInstance({
    SUBJECT_SALT,
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
    STATE_STORE_BACKEND: 'memory',
    UPSTREAM_OIDC_LOCAL_CLIENT_ID: 'example.test:upstream-client',
    UPSTREAM_OIDC_LOCAL_CLIENT_SECRET: 'upstream-secret',
    UPSTREAM_OIDC_LOCAL_ISSUER: stub.issuer,
    SAG_LOCAL_IDENTITIES: {
      get: async () => record,
      replace: async (_key, revision, next) => {
        writeAttempts += 1;
        if (failAllWrites || writeAttempts === 1 || record.revision !== revision) return false;
        record = next;
        return true;
      },
      verifyArgon2id: async (_hash, password) => password === 'correct horse battery staple',
    },
  });

  const localSignIn = await submitLocalPassword(instance, {
    acr: ACR.LOCAL_PASSWORD,
    password: 'correct horse battery staple',
  });
  assert.equal(localSignIn.response.status, 303);
  const localCode = new URL(localSignIn.response.headers.get('location')).searchParams.get('code');
  const localTokens = await redeem(instance, {
    authCode: localCode,
    verifier: localSignIn.verifier,
  });
  const localClaims = decodeJwt(localTokens.body.id_token).payload;

  async function startUpstream() {
    const { verifier, challenge } = await pkce();
    const first = await instance.raw(authorizeUrl({ challenge, prompt: 'login' }).path);
    const emailTx = extractField(await first.text());
    const passwordPage = await instance.postForm('/authorize/email', { tx: emailTx, email: EMAIL });
    const upstreamTx = extractField(await passwordPage.text());
    const handoff = await instance.postForm('/authorize/upstream', {
      tx: upstreamTx,
      upstream: 'oidc/local',
    });
    assert.equal(handoff.status, 303);
    const sent = readUpstreamRedirect(handoff);
    await stub.expect({
      audience: 'upstream-client',
      nonce: sent.nonce,
      claims: { email: EMAIL, email_verified: true, name: 'Jamie Taylor' },
    });
    return { verifier, sent };
  }

  stub.state.refreshToken = 'upstream-refresh-secret';
  const first = await startUpstream();
  const callbackPath = '/callback?code=upstream-code&state=' + encodeURIComponent(first.sent.state);
  const completed = await instance.raw(callbackPath);
  assert.equal(completed.status, 303);
  assert.equal(writeAttempts, 2, 'one CAS conflict is retried against a freshly read record');
  assert.equal(record.revision, 2);
  assert.ok(record.upstreams[0].refresh_token);
  assert.doesNotMatch(JSON.stringify(record), /upstream-refresh-secret/);

  const code = new URL(completed.headers.get('location')).searchParams.get('code');
  const tokens = await redeem(instance, { authCode: code, verifier: first.verifier });
  assert.equal(tokens.res.status, 200, JSON.stringify(tokens.body));
  const claims = decodeJwt(tokens.body.id_token).payload;
  assert.equal(claims.email_verified, true);
  assert.equal(claims.sid, localClaims.sid, 'an exact link keeps the existing local principal and session id');
  assert.equal(
    claims.sub,
    await subjectForLocalIdentity(loadConfig(instance.env), IDENTITY_ID, { clientId: DEV_CLIENT }),
  );

  failAllWrites = true;
  const failedPersistence = await instance.raw(callbackPath);
  assert.equal(failedPersistence.status, 500, 'a refresh credential is never silently dropped');

  failAllWrites = false;
  record = { ...record, revision: record.revision + 1, upstreams: [] };
  stub.state.refreshToken = undefined;
  const unlinked = await startUpstream();
  const unlinkedResponse = await instance.raw(
    '/callback?code=upstream-code&state=' + encodeURIComponent(unlinked.sent.state),
  );
  assert.equal(unlinkedResponse.status, 303);
  const unlinkedCode = new URL(unlinkedResponse.headers.get('location')).searchParams.get('code');
  const unlinkedTokens = await redeem(instance, {
    authCode: unlinkedCode,
    verifier: unlinked.verifier,
  });
  const unlinkedClaims = decodeJwt(unlinkedTokens.body.id_token).payload;
  assert.notEqual(unlinkedClaims.sid, localClaims.sid, 'an unlinked upstream starts a distinct principal session');
  assert.equal(
    unlinkedClaims.sub,
    await subjectFor(loadConfig(instance.env), EMAIL, { clientId: DEV_CLIENT }),
  );

  stub.state.tokenError = 'invalid_grant';
  const fallback = await startUpstream();
  const fallbackResponse = await instance.raw(
    '/callback?code=upstream-code&state=' + encodeURIComponent(fallback.sent.state),
  );
  assert.equal(fallbackResponse.status, 400);
  const fallbackBody = await fallbackResponse.text();
  assert.match(fallbackBody, /That sign-in did not complete/);
  assert.match(fallbackBody, /use your password/i);
});

test('a local-password grant never publishes email_verified', async () => {
  const config = configWith();
  const recordKey = await localIdentityKey(config, EMAIL);
  const session = newSession(config, {
    email: EMAIL,
    emailVerified: false,
    acr: ACR.LOCAL_MFA,
    amr: [AMR.PASSWORD, AMR.OTP, AMR.MFA],
    localIdentityId: IDENTITY_ID,
    localIdentityKey: recordKey,
    localSecurityVersion: 7,
  });
  const grant = await roundTripGrant(config, session);

  assert.equal(grant.email_verified, false, 'the sealed code carries the evidence decision explicitly');
  assert.equal(grant.local_identity_id, IDENTITY_ID);
  assert.equal(grant.local_identity_key, recordKey);
  assert.equal(grant.local_security_version, 7);

  const claims = await idTokenClaims(config, {
    grant,
    audience: grant.client_id,
  });
  assert.equal(claims.email, EMAIL);
  assert.equal(
    Object.hasOwn(claims, 'email_verified'),
    false,
    'OIDC consumers must see absence, rather than a false claim they may mishandle',
  );

  const accessToken = await issueAccessToken(config, grant);
  const opened = await readAccessToken(config, accessToken);
  assert.equal(opened.email_verified, false);
  assert.equal(opened.local_identity_id, IDENTITY_ID);
  assert.equal(opened.local_security_version, 7);

  const claimsFromUserinfo = await userinfo(config, accessToken);
  assert.equal(claimsFromUserinfo.email, EMAIL);
  assert.equal(Object.hasOwn(claimsFromUserinfo, 'email_verified'), false);
});

test('pre-feature session, code and access-token evidence migrates as verified', async () => {
  const config = configWith();
  const now = nowSeconds();
  const legacySession = {
    v: 1,
    sid: 'legacy-session-id',
    email: EMAIL,
    acr: ACR.OTP,
    amr: [AMR.OTP, AMR.EMAIL],
    auth_time: now,
    iat: now,
    exp: now + 300,
    abs: now + 300,
  };
  const sessionToken = await seal(config.secrets[0], 'session', legacySession);
  const session = await readSessionByName(
    config,
    new Request(ISSUER + '/authorize', {
      headers: { cookie: 'legacy_session=' + encodeURIComponent(sessionToken) },
    }),
    'legacy_session',
  );
  assert.equal(session.emailVerified, true);

  const legacyCode = await seal(config.secrets[0], 'code', {
    v: 1,
    jti: 'legacy-code-id',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    scope: ['openid', 'email'],
    sub: 'legacy-subject',
    email: EMAIL,
    acr: ACR.OTP,
    amr: [AMR.OTP, AMR.EMAIL],
    auth_time: now,
    sid: 'legacy-session-id',
    iat: now,
    exp: now + 60,
  });
  const grant = await redeemCode(config, {
    code: legacyCode,
    clientId: DEV_CLIENT,
    redirectUri: DEV_REDIRECT,
  });
  assert.equal(grant.email_verified, true);

  const legacyAccess = await seal(config.secrets[0], 'access', {
    v: 1,
    sub: 'legacy-subject',
    client_id: DEV_CLIENT,
    scope: ['openid', 'email'],
    email: EMAIL,
    acr: ACR.OTP,
    amr: [AMR.OTP, AMR.EMAIL],
    auth_time: now,
    sid: 'legacy-session-id',
    iat: now,
    exp: now + 300,
  });
  assert.equal((await readAccessToken(config, legacyAccess)).email_verified, true);
});

test('an exact linked upstream may verify the email while retaining the local subject', async () => {
  const config = configWith();
  const linked = newSession(config, {
    email: EMAIL,
    emailVerified: true,
    acr: ACR.FEDERATED_MFA,
    amr: [AMR.FEDERATED, AMR.MFA],
    upstream: 'google:example-test',
    localIdentityId: IDENTITY_ID,
    localSecurityVersion: 4,
  });
  const grant = await roundTripGrant(config, linked);
  const claims = await idTokenClaims(config, {
    grant,
    audience: grant.client_id,
  });
  assert.equal(claims.email_verified, true);
  assert.equal(claims.sub, await subjectForLocalIdentity(config, IDENTITY_ID, { clientId: grant.client_id }));

  const accessToken = await issueAccessToken(config, grant);
  assert.equal((await userinfo(config, accessToken)).email_verified, true);

  const withoutEmailScope = await idTokenClaims(config, {
    grant: { ...grant, scope: ['openid'] },
    audience: grant.client_id,
  });
  assert.equal(Object.hasOwn(withoutEmailScope, 'email'), false);
  assert.equal(Object.hasOwn(withoutEmailScope, 'email_verified'), false);
});

test('the token endpoint revalidates mutable local identity state before issuing anything', async () => {
  const active = await exchangeLocalCode(storedIdentity());
  assert.equal(active.response.status, 200, JSON.stringify(active.body));
  assert.equal(
    Object.hasOwn(decodeJwt(active.body.id_token).payload, 'email_verified'),
    false,
    'the real token endpoint must preserve the local-email distinction',
  );

  const changed = await exchangeLocalCode(storedIdentity({ security_version: 4 }));
  assert.equal(changed.response.status, 400);
  assert.equal(changed.body.error, 'invalid_grant');

  const disabled = await exchangeLocalCode(storedIdentity({ disabled: true }));
  assert.equal(disabled.response.status, 400);
  assert.equal(disabled.body.error, 'invalid_grant');

  const deleted = await exchangeLocalCode(undefined);
  assert.equal(deleted.response.status, 400);
  assert.equal(deleted.body.error, 'invalid_grant');

  const tagged = await exchangeLocalCode(storedIdentity(), {
    authenticationEmail: TAGGED_EMAIL,
    publicEmail: EMAIL,
  });
  assert.equal(
    tagged.response.status,
    200,
    'RP-specific plus-tag sanitisation must not change which authoritative local record is revalidated',
  );
});

test('reauthentication replaces local identity and verification evidence instead of inheriting it', () => {
  const config = configWith();
  const recordKey = 'a'.repeat(64);
  const local = newSession(config, {
    email: EMAIL,
    acr: ACR.LOCAL_PASSWORD,
    amr: [AMR.PASSWORD],
    localIdentityId: IDENTITY_ID,
    localIdentityKey: recordKey,
    localSecurityVersion: 2,
  });
  assert.equal(local.emailVerified, false);

  const unlinked = reauthenticate(config, local, {
    email: EMAIL,
    emailVerified: true,
    acr: ACR.FEDERATED,
    amr: [AMR.FEDERATED],
  });
  assert.equal(unlinked.emailVerified, true);
  assert.equal(unlinked.localIdentityId, undefined);
  assert.equal(unlinked.localIdentityKey, undefined);
  assert.equal(unlinked.localSecurityVersion, undefined);

  const linked = reauthenticate(config, unlinked, {
    email: EMAIL,
    emailVerified: true,
    acr: ACR.FEDERATED,
    amr: [AMR.FEDERATED],
    claims: { name: 'Upstream name' },
    localIdentityId: IDENTITY_ID,
    localIdentityKey: recordKey,
    localSecurityVersion: 3,
  });
  assert.equal(linked.localIdentityId, IDENTITY_ID);
  assert.equal(linked.localIdentityKey, recordKey);
  assert.equal(linked.localSecurityVersion, 3);
  assert.deepEqual(linked.claims, { name: 'Upstream name' });

  const passwordAgain = reauthenticate(config, linked, {
    email: EMAIL,
    acr: ACR.LOCAL_PASSWORD,
    amr: [AMR.PASSWORD],
    localIdentityId: IDENTITY_ID,
    localIdentityKey: recordKey,
    localSecurityVersion: 3,
  });
  assert.equal(passwordAgain.emailVerified, false);
  assert.equal(passwordAgain.claims, undefined, 'local reauthentication must not inherit upstream profile claims');
});

test('local identity configuration fails closed unless routing, attempt limits and a stable index key are explicit', () => {
  const missingDomains = configWith({
    LOCAL_IDENTITIES_BACKEND: 'file',
    STATE_STORE_BACKEND: 'memory',
  });
  assert.throws(() => assertUsable(missingDomains), /LOCAL_IDENTITY_DOMAINS is empty/);

  const missingState = configWith({
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
  });
  assert.throws(() => assertUsable(missingState), /requires an atomic STATE_STORE_BACKEND/);

  const missingSalt = loadConfig({
    SAG_ISSUER: ISSUER,
    SAG_SECRET: SECRET,
    LOCAL_IDENTITIES_BACKEND: 'file',
    LOCAL_IDENTITY_DOMAINS: 'example.test',
    STATE_STORE_BACKEND: 'memory',
  });
  assert.throws(() => assertUsable(missingSalt), /SUBJECT_SALT must be set explicitly/);

  const weakSalt = localConfig({ SUBJECT_SALT: 'too-short' });
  assert.throws(
    () => assertUsable(weakSalt),
    /Local identity filenames require an unguessable keyed digest/,
  );

  assert.throws(
    () => configWith({ LOCAL_IDENTITIES_BACKEND: 'sqlite' }),
    (err) => err instanceof ConfigError && /LOCAL_IDENTITIES_BACKEND must be one of none, file/.test(err.message),
  );
  for (const domains of ['localhost', 'https://example.test', '*.', '-bad.example.test', 'bad-.example.test']) {
    assert.throws(
      () => configWith({ LOCAL_IDENTITY_DOMAINS: domains }),
      (err) => err instanceof ConfigError && /LOCAL_IDENTITY_DOMAINS contains an invalid domain/.test(err.message),
      domains,
    );
  }

  const config = localConfig({
    OTP_ENABLED: 'false',
    LOCAL_IDENTITY_DOMAINS: 'EXAMPLE.TEST,*.Staff.Example.Test,example.test,*',
    LOCAL_AUTH_ATTEMPT_WINDOW: '420',
    LOCAL_AUTH_MAX_ATTEMPTS: '8',
    LOCAL_AUTH_NETWORK_MAX_ATTEMPTS: '40',
    LOCAL_PASSWORD_MAX_BYTES: '2048',
    LOCAL_TOTP_SKEW: '2',
    LOCAL_ARGON2_CONCURRENCY: '3',
  });
  assert.doesNotThrow(() => assertUsable(config));
  assert.deepEqual(config.localIdentities.domains, ['example.test', '*.staff.example.test', '*']);
  assert.equal(config.localIdentities.attemptWindowSeconds, 420);
  assert.equal(config.localIdentities.maxAttempts, 8);
  assert.equal(config.localIdentities.networkMaxAttempts, 40);
  assert.equal(config.localIdentities.maxPasswordBytes, 2048);
  assert.equal(config.localIdentities.totpSkew, 2);
  assert.equal(config.localIdentities.argon2Concurrency, 3);
  assert.equal(
    config.problems.some((problem) => /nobody could ever sign in/.test(problem)),
    false,
    'local accounts are a viable authentication method without OTP or upstreams',
  );
});

test('local identity domain routing is public policy and never depends on whether a record exists', () => {
  const exact = localConfig({ LOCAL_IDENTITY_DOMAINS: 'Example.Test' });
  assert.equal(localIdentityAllowed(exact, 'Jamie.Taylor@EXAMPLE.TEST'), true);
  assert.equal(localIdentityAllowed(exact, 'jamie@other.test'), false);
  assert.equal(localIdentityAllowed(exact, 'not-an-address'), false);

  const subtree = localConfig({ LOCAL_IDENTITY_DOMAINS: '*.staff.example.test' });
  assert.equal(localIdentityAllowed(subtree, 'jamie@staff.example.test'), true);
  assert.equal(localIdentityAllowed(subtree, 'jamie@uk.staff.example.test'), true);
  assert.equal(localIdentityAllowed(subtree, 'jamie@example.test'), false);

  const any = localConfig({ LOCAL_IDENTITY_DOMAINS: '*' });
  assert.equal(localIdentityAllowed(any, 'jamie@somewhere.test'), true);

  const disabled = configWith({ LOCAL_IDENTITY_DOMAINS: '*' });
  assert.equal(localIdentityAllowed(disabled, 'jamie@somewhere.test'), false);
});
