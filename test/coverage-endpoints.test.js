// Focused tests to achieve line coverage across endpoints, router, session, remember-me, store, and ui.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { createInstance, DEV_CLIENT, DEV_REDIRECT } from './harness.js';
import { OAuthError, UserFacingError } from '../src/util/errors.js';
import { ACR } from '../src/acr.js';
import { nowSeconds, b64uJson } from '../src/util/bytes.js';
import { seal } from '../src/crypto/secrets.js';

import {
  handleEmailSubmit,
  handleOtpRequest,
  handleContinue,
  handleChooseUpstream,
  handleCallback,
} from '../src/endpoints/authorize.js';
import { failureResponse } from '../src/endpoints/respond.js';
import { readRememberedEmail, REMEMBER_ME_COOKIE } from '../src/remember-me.js';
import { sessionCookie, clearSessionCookie, newSession } from '../src/session.js';
import { createMemoryStore, createDynamoStore, createStateStore } from '../src/store/index.js';
import { contentSecurityPolicy } from '../src/ui/csp.js';
import { continuePage } from '../src/ui/pages.js';
import {
  sealTransaction,
  sealUpstreamState,
  STAGE,
} from '../src/oauth/transaction.js';
import { issueAccessToken } from '../src/oauth/tokens.js';
import { ROUTES } from '../src/router.js';

function baseEnv(overrides = {}) {
  return {
    SAG_ISSUER: 'http://localhost:8787',
    SAG_SECRET: 'test-secret-'.repeat(4),
    SUBJECT_SALT: 'salt-'.repeat(8),
    LOG_LEVEL: 'silent',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. src/endpoints/authorize.js
// ---------------------------------------------------------------------------

test('authorize: loadTransaction returns startAgainResponse when transaction is expired (lines 262-268)', async () => {
  const config = loadConfig(baseEnv());
  const now = nowSeconds();
  const tx = {
    v: 1,
    id: 'tx-expired',
    stage: STAGE.EMAIL,
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-123',
    exp: now + 1, // valid when unsealed
  };
  const sealed = await sealTransaction(config, tx);

  const ctx = {
    config,
    request: new Request('http://localhost:8787/authorize/email', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: sealed, email: 'user@example.org' }).toString(),
    }),
    url: new URL('http://localhost:8787/authorize/email'),
    path: '/authorize/email',
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
    log: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    route: (p) => p,
    resolveClient: async () => ({ id: DEV_CLIENT, redirectUris: [DEV_REDIRECT] }),
  };

  const originalNow = Date.now;
  let callCount = 0;
  try {
    // Return unexpired time during unseal, then expired time during expired(tx)
    Date.now = () => {
      callCount++;
      return (callCount <= 1 ? now : now + 10) * 1000;
    };
    const res = await handleEmailSubmit(ctx);
    assert.equal(res.status, 400);
    const text = await res.text();
    assert.match(text, /This sign-in attempt took too long and has expired/);
  } finally {
    Date.now = originalNow;
  }
});

test('authorize: sendOtp returns error when resends exceed maxResends (lines 366-373)', async () => {
  const sag = createInstance();
  const config = loadConfig(baseEnv());
  const tx = {
    v: 1,
    id: 'tx-resends',
    stage: STAGE.OTP,
    email: 'user@example.org',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-123',
    otp: {
      digest: 'some-digest',
      exp: nowSeconds() + 300,
      attempts: 0,
      resends: config.otp.maxResends + 1, // exceeds maxResends
      iat: nowSeconds(),
    },
    exp: nowSeconds() + 600,
  };
  const sealed = await sealTransaction(config, tx);

  const res = await sag.postForm('/authorize/resend', { tx: sealed });
  assert.equal(res.status, 400);
  const text = await res.text();
  assert.match(text, /Too many codes requested/);
});

test('authorize: sendOtp handles emailSender.send failure (lines 430-439)', async () => {
  const config = loadConfig(baseEnv());
  const tx = {
    v: 1,
    id: 'tx-send-fail',
    stage: STAGE.EMAIL,
    client_id: DEV_CLIENT,
    client_name: 'Dev App',
    redirect_uri: DEV_REDIRECT,
    state: 'state-123',
    exp: nowSeconds() + 600,
  };
  const sealed = await sealTransaction(config, tx);

  const ctx = {
    config,
    request: new Request('http://localhost:8787/authorize/email', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: sealed, email: 'user@example.org' }).toString(),
    }),
    url: new URL('http://localhost:8787/authorize/email'),
    path: '/authorize/email',
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
    log: {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
    },
    route: (p) => p,
    resolveClient: async (id) => (id === DEV_CLIENT ? { id: DEV_CLIENT, clientName: 'Dev App', redirectUris: [DEV_REDIRECT] } : undefined),
    emailSender: {
      name: 'broken-mail',
      send: async () => {
        throw new Error('Connection refused by SMTP host');
      },
    },
  };

  const response = await handleEmailSubmit(ctx);
  assert.equal(response.status, 400);
  const text = await response.text();
  assert.match(text, /We could not send your code/);
});

test('authorize: handleOtpRequest handles disallowed OTP / required federation vs allowed (lines 445-452)', async () => {
  const config = loadConfig(baseEnv());

  // 1) Disallowed / requires federation
  const txFed = {
    v: 1,
    id: 'tx-fed',
    stage: STAGE.CHOOSE,
    email: 'user@example.org',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-123',
    acr_values: [ACR.FEDERATED_MFA],
    exp: nowSeconds() + 600,
  };
  const sealedFed = await sealTransaction(config, txFed);

  const ctxFed = {
    config,
    request: new Request('http://localhost:8787/authorize/otp-request', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: sealedFed }).toString(),
    }),
    url: new URL('http://localhost:8787/authorize/otp-request'),
    path: '/authorize/otp-request',
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
    log: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    route: (p) => p,
    resolveClient: async () => ({ id: DEV_CLIENT, redirectUris: [DEV_REDIRECT] }),
  };

  const resFed = await handleOtpRequest(ctxFed);
  assert.equal(resFed.status, 400);
  const textFed = await resFed.text();
  assert.match(textFed, /Signing in with an email code is not available for this request/);

  // 2) Allowed OTP
  const txAllowed = {
    v: 1,
    id: 'tx-allowed',
    stage: STAGE.CHOOSE,
    email: 'user@example.org',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-123',
    exp: nowSeconds() + 600,
  };
  const sealedAllowed = await sealTransaction(config, txAllowed);

  const ctxAllowed = {
    config,
    request: new Request('http://localhost:8787/authorize/otp-request', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: sealedAllowed }).toString(),
    }),
    url: new URL('http://localhost:8787/authorize/otp-request'),
    path: '/authorize/otp-request',
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
    log: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    route: (p) => p,
    resolveClient: async () => ({ id: DEV_CLIENT, redirectUris: [DEV_REDIRECT] }),
    emailSender: { name: 'dev', send: async () => ({ code: '123456789' }) },
  };

  const resAllowed = await handleOtpRequest(ctxAllowed);
  assert.equal(resAllowed.status, 200);
});

test('authorize: handleRestart resets transaction to email stage (lines 519-522)', async () => {
  const sag = createInstance();
  const config = loadConfig(baseEnv());
  const tx = {
    v: 1,
    id: 'tx-restart',
    stage: STAGE.OTP,
    email: 'user@example.org',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-123',
    otp: { digest: 'd', exp: nowSeconds() + 300 },
    exp: nowSeconds() + 600,
  };
  const sealed = await sealTransaction(config, tx);

  const res = await sag.postForm('/authorize/restart', { tx: sealed });
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.match(text, /Enter your email address/);
});

test('authorize: handleContinue with stale session renders email page with prefilled email (lines 540-541)', async () => {
  const config = loadConfig(baseEnv());
  const tx = {
    v: 1,
    id: 'tx-cont',
    stage: STAGE.CONTINUE,
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-123',
    max_age: 10,
    exp: nowSeconds() + 600,
  };
  const sealed = await sealTransaction(config, tx);

  // Session authenticated in the past (auth_time 500s ago), exceeding max_age: 10
  const session = newSession(config, {
    email: 'stale-user@example.org',
    acr: ACR.OTP,
    amr: ['otp'],
  });
  session.auth_time = nowSeconds() - 500;
  // Use shared session cookie (undefined clientId)
  const sessionCookieHeader = await sessionCookie(config, session, undefined);

  const ctx = {
    config,
    request: new Request('http://localhost:8787/authorize/continue', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        cookie: sessionCookieHeader.split(';')[0],
      },
      body: new URLSearchParams({ tx: sealed }).toString(),
    }),
    url: new URL('http://localhost:8787/authorize/continue'),
    path: '/authorize/continue',
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
    log: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    route: (p) => p,
    resolveClient: async () => ({ id: DEV_CLIENT, redirectUris: [DEV_REDIRECT] }),
  };

  const res = await handleContinue(ctx);
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.match(text, /stale-user@example\.org/);
});

test('authorize: startUpstream error fallback and failure response (lines 555-562)', async () => {
  const config = loadConfig(baseEnv({
    UPSTREAM_OIDC_BROKEN_CLIENT_ID: 'example.org:client',
    UPSTREAM_OIDC_BROKEN_CLIENT_SECRET: 'secret',
    UPSTREAM_OIDC_BROKEN_ISSUER: 'https://broken.invalid',
  }));

  const txFallback = {
    v: 1,
    id: 'tx-up-fail',
    stage: STAGE.EMAIL,
    email: 'user@example.org',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-123',
    exp: nowSeconds() + 600,
  };
  const sealedFallback = await sealTransaction(config, txFallback);

  // 1) Fallback to email code when OTP allowed
  const ctxFallback = {
    config,
    request: new Request('http://localhost:8787/authorize/upstream', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: sealedFallback, upstream: 'oidc/broken' }).toString(),
    }),
    url: new URL('http://localhost:8787/authorize/upstream'),
    path: '/authorize/upstream',
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
    log: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    route: (p) => p,
    resolveClient: async () => ({ id: DEV_CLIENT, redirectUris: [DEV_REDIRECT] }),
    emailSender: { name: 'dev', send: async () => ({ code: '123456789' }) },
    fetch: async () => {
      throw new Error('Upstream unreachable');
    },
  };

  const resFallback = await handleChooseUpstream(ctxFallback);
  assert.equal(resFallback.status, 200); // Renders OTP page

  // 2) No fallback (federation required) -> 303 failureResponse with serverError
  const txNoFallback = {
    ...txFallback,
    acr_values: [ACR.FEDERATED_MFA],
  };
  const sealedNoFallback = await sealTransaction(config, txNoFallback);

  const ctxNoFallback = {
    ...ctxFallback,
    request: new Request('http://localhost:8787/authorize/upstream', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx: sealedNoFallback, upstream: 'oidc/broken' }).toString(),
    }),
  };

  const resNoFallback = await handleChooseUpstream(ctxNoFallback);
  assert.equal(resNoFallback.status, 303);
  const loc = new URL(resNoFallback.headers.get('location'));
  assert.equal(loc.searchParams.get('error'), 'server_error');
});

test('authorize: handleCallback upstream error with prompt=none returns login_required (lines 609-610)', async () => {
  const config = loadConfig(baseEnv());
  const stateTx = {
    v: 1,
    id: 'tx-state-none',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-xyz',
    prompt: ['none'],
    upstream: { id: 'test-up' },
    exp: nowSeconds() + 600,
  };
  const sealedState = await sealUpstreamState(config, stateTx);

  const ctx = {
    config,
    request: new Request(`http://localhost:8787/callback?error=interaction_required&state=${encodeURIComponent(sealedState)}`),
    url: new URL(`http://localhost:8787/callback?error=interaction_required&state=${encodeURIComponent(sealedState)}`),
    path: '/callback',
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
    log: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    resolveClient: async () => ({ id: DEV_CLIENT, redirectUris: [DEV_REDIRECT] }),
  };

  const res = await handleCallback(ctx);
  assert.equal(res.status, 303);
  const loc = new URL(res.headers.get('location'));
  assert.equal(loc.searchParams.get('error'), 'login_required');
  assert.equal(loc.searchParams.get('state'), 'state-xyz');
});

test('authorize: offerFallback returns access_denied when no OTP fallback possible (line 711)', async () => {
  const config = loadConfig(baseEnv({
    UPSTREAM_OIDC_CORP_CLIENT_ID: 'corp.test:client',
    UPSTREAM_OIDC_CORP_CLIENT_SECRET: 'secret',
    UPSTREAM_OIDC_CORP_ISSUER: 'https://corp.test',
  }));

  // Transaction requiring federation and no other upstream candidates
  const stateTx = {
    v: 1,
    id: 'tx-state-nofallback',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    state: 'state-abc',
    email: 'employee@corp.test',
    acr_values: [ACR.FEDERATED_MFA],
    upstream: { id: 'oidc/corp' },
    exp: nowSeconds() + 600,
  };
  const sealedState = await sealUpstreamState(config, stateTx);

  const ctx = {
    config,
    request: new Request(`http://localhost:8787/callback?error=temporarily_unavailable&state=${encodeURIComponent(sealedState)}`),
    url: new URL(`http://localhost:8787/callback?error=temporarily_unavailable&state=${encodeURIComponent(sealedState)}`),
    path: '/callback',
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
    log: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    resolveClient: async () => ({ id: DEV_CLIENT, redirectUris: [DEV_REDIRECT] }),
  };

  const res = await handleCallback(ctx);
  assert.equal(res.status, 303);
  const loc = new URL(res.headers.get('location'));
  assert.equal(loc.searchParams.get('error'), 'access_denied');
});

// ---------------------------------------------------------------------------
// 2. src/endpoints/logout.js
// ---------------------------------------------------------------------------

test('logout: clientFromHint reads audience from valid JWT or returns undefined on error (lines 183-184, 188-189)', async () => {
  const sag = createInstance();

  // Valid JWT hint with single audience
  const header = b64uJson({ alg: 'none', typ: 'JWT' });
  const payload1 = b64uJson({ aud: DEV_CLIENT, sub: 'user1' });
  const hint1 = `${header}.${payload1}.`;

  const res1 = await sag.raw(`/logout?id_token_hint=${hint1}`);
  assert.equal(res1.status, 200);

  // Valid JWT hint with array audience
  const payload2 = b64uJson({ aud: [DEV_CLIENT], sub: 'user1' });
  const hint2 = `${header}.${payload2}.`;

  const res2 = await sag.raw(`/logout?id_token_hint=${hint2}`);
  assert.equal(res2.status, 200);

  // Malformed hint causing decodeJwt to throw
  const resBad = await sag.raw('/logout?id_token_hint=not.a.valid.jwt-at-all');
  assert.equal(resBad.status, 200);
});

// ---------------------------------------------------------------------------
// 3. src/endpoints/respond.js
// ---------------------------------------------------------------------------

test('respond: failureResponse maps all titleFor error codes (lines 98, 101, 103, 105, 107)', () => {
  const config = loadConfig(baseEnv());
  const ctx = {
    config,
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
  };

  // access_denied (line 98)
  const r1 = failureResponse(ctx, new OAuthError('access_denied', 'denied'));
  assert.equal(r1.status, 400);

  // login_required and interaction_required (line 101)
  const r2 = failureResponse(ctx, new OAuthError('login_required', 'login needed'));
  assert.equal(r2.status, 400);
  const r3 = failureResponse(ctx, new OAuthError('interaction_required', 'interact needed'));
  assert.equal(r3.status, 400);

  // unmet_authentication_requirements (line 103)
  const r4 = failureResponse(ctx, new OAuthError('unmet_authentication_requirements', 'stronger auth'));
  assert.equal(r4.status, 400);

  // server_error (line 105)
  const r5 = failureResponse(ctx, new OAuthError('server_error', 'internal error', { status: 500 }));
  assert.equal(r5.status, 500);

  // default / generic error (line 107)
  const r6 = failureResponse(ctx, new OAuthError('unsupported_grant_type', 'unsupported'));
  assert.equal(r6.status, 400);
  const r7 = failureResponse(ctx, new Error('unexpected non-oauth error'));
  assert.equal(r7.status, 400);
});

// ---------------------------------------------------------------------------
// 4. src/endpoints/userinfo.js
// ---------------------------------------------------------------------------

test('userinfo: presentedToken extracts token from POST form body (lines 39-43)', async () => {
  const sag = createInstance();
  const config = loadConfig(baseEnv());

  const token = await issueAccessToken(config, {
    sub: 'user-12345',
    client_id: DEV_CLIENT,
    scope: ['openid', 'email', 'profile'],
    email: 'user@example.org',
    acr: ACR.OTP,
    amr: ['otp'],
    auth_time: nowSeconds(),
    claims: { name: 'Test User' },
  });

  const res = await sag.postForm('/userinfo', { access_token: token });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.sub, 'user-12345');
  assert.equal(body.email, 'user@example.org');
  assert.equal(body.name, 'Test User');
});

// ---------------------------------------------------------------------------
// 5. src/remember-me.js
// ---------------------------------------------------------------------------

test('remember-me: readRememberedEmail returns undefined on invalid version, expiry, format, or SealError (lines 34-35, 38-40)', async () => {
  const config = loadConfig(baseEnv());

  // 1) v !== 1
  const badVersion = await seal(config.secrets[0], 'remember-me', { v: 2, email: 'user@example.org', exp: nowSeconds() + 1000 });
  const req1 = new Request('http://localhost:8787/', { headers: { cookie: `${REMEMBER_ME_COOKIE}=${badVersion}` } });
  assert.equal(await readRememberedEmail(config, req1), undefined);

  // 2) exp is not finite or expired
  const expiredVal = await seal(config.secrets[0], 'remember-me', { v: 1, email: 'user@example.org', exp: nowSeconds() - 10 });
  const req2 = new Request('http://localhost:8787/', { headers: { cookie: `${REMEMBER_ME_COOKIE}=${expiredVal}` } });
  assert.equal(await readRememberedEmail(config, req2), undefined);

  // 3) not looksLikeEmail
  const badEmail = await seal(config.secrets[0], 'remember-me', { v: 1, email: 'invalid-email', exp: nowSeconds() + 1000 });
  const req3 = new Request('http://localhost:8787/', { headers: { cookie: `${REMEMBER_ME_COOKIE}=${badEmail}` } });
  assert.equal(await readRememberedEmail(config, req3), undefined);

  // 4) SealError (tampered ciphertext)
  const req4 = new Request('http://localhost:8787/', { headers: { cookie: `${REMEMBER_ME_COOKIE}=k1.remember-me.AAAA.BBBB` } });
  assert.equal(await readRememberedEmail(config, req4), undefined);

  // 5) Non-SealError rethrows (e.g. TypeError from getter)
  const badConfig = {
    get secrets() {
      throw new TypeError('Unexpected config error');
    },
  };
  const req5 = new Request('http://localhost:8787/', { headers: { cookie: `${REMEMBER_ME_COOKIE}=some.token.value.here` } });
  await assert.rejects(() => readRememberedEmail(badConfig, req5), TypeError);
});

// ---------------------------------------------------------------------------
// 6. src/router.js
// ---------------------------------------------------------------------------

test('router: methodNotAllowed, OAuthError failure, UserFacingError, and unexpected errors (lines 181-182, 220-221, 223-224, 231)', async () => {
  const sag = createInstance();

  // 1) Method not allowed on route (lines 181-182)
  const res405 = await sag.raw('/authorize', { method: 'PUT' });
  assert.equal(res405.status, 405);
  assert.ok(res405.headers.get('allow'));

  // 2) OAuthError on non-API route (lines 220-221)
  const resOAuthErr = await sag.raw('/authorize?response_type=code');
  assert.equal(resOAuthErr.status, 400);
  assert.equal(resOAuthErr.headers.get('content-type'), 'text/html; charset=utf-8');

  // 3) UserFacingError on route (lines 223-224)
  // Register a mock handler on a temporary test route in ROUTES
  const dummyRoute = {
    path: '/test-user-facing-error',
    methods: ['GET'],
    handler: async () => {
      throw new UserFacingError('Problem Title', 'User facing problem detail', 400);
    },
  };
  ROUTES.push(dummyRoute);
  try {
    const resUserFacing = await sag.raw('/test-user-facing-error');
    assert.equal(resUserFacing.status, 400);
    const text = await resUserFacing.text();
    assert.match(text, /User facing problem detail/);
  } finally {
    const idx = ROUTES.indexOf(dummyRoute);
    if (idx >= 0) ROUTES.splice(idx, 1);
  }

  // 4) Unexpected bug error on non-API route (line 231)
  const dummyCrashRoute = {
    path: '/test-server-crash',
    methods: ['GET'],
    handler: async () => {
      throw new Error('Unexpected database blowout');
    },
  };
  ROUTES.push(dummyCrashRoute);
  try {
    const resCrash = await sag.raw('/test-server-crash');
    assert.equal(resCrash.status, 500);
    const text = await resCrash.text();
    assert.match(text, /Something went wrong while signing you in/);
  } finally {
    const idx = ROUTES.indexOf(dummyCrashRoute);
    if (idx >= 0) ROUTES.splice(idx, 1);
  }
});

// ---------------------------------------------------------------------------
// 7. src/session.js
// ---------------------------------------------------------------------------

test('session: clearSessionCookie formats Set-Cookie header with Max-Age=0 (lines 167-174)', async () => {
  const config = loadConfig(baseEnv());
  const cookieStr = await clearSessionCookie(config, DEV_CLIENT);
  assert.match(cookieStr, /Max-Age=0/);
  assert.match(cookieStr, /Path=\//);
  assert.match(cookieStr, /SameSite=Lax/);
});

// ---------------------------------------------------------------------------
// 8. src/store/index.js
// ---------------------------------------------------------------------------

test('store: memory store has() deletes expired entry and returns false (lines 79-81)', async () => {
  const store = createMemoryStore({ maxEntries: 10 });
  await store.claim('key-exp', 1);

  // Directly verify has() behavior when item has expired in the store
  const originalNow = Date.now;
  try {
    Date.now = () => originalNow() + 5000; // fast-forward 5s
    const exists = await store.has('key-exp');
    assert.equal(exists, false);
  } finally {
    Date.now = originalNow;
  }
});

test('store: dynamo store has() throws on non-200 response (lines 229-231)', async () => {
  const config = {
    stateStore: {
      backend: 'dynamodb',
      table: 'sag-state',
      region: 'eu-west-2',
      endpoint: 'https://dynamodb.mock.local/',
    },
  };

  const env = {
    AWS_ACCESS_KEY_ID: 'test-key',
    AWS_SECRET_ACCESS_KEY: 'test-secret',
  };

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response('Internal DynamoDB Error', { status: 500 });
    const store = createDynamoStore(config, env);
    await assert.rejects(
      () => store.has('some-id'),
      /state store read failed \(HTTP 500\)/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('store: createStateStore throws on unknown backend (line 275)', async () => {
  const config = { stateStore: { backend: 'unsupported-backend-type' } };
  await assert.rejects(
    () => createStateStore(config, {}),
    /unknown state store backend: unsupported-backend-type/,
  );
});

// ---------------------------------------------------------------------------
// 9. src/ui/csp.js
// ---------------------------------------------------------------------------

test('ui/csp: contentSecurityPolicy handles invalid customCssRemoteUrl and clientLogoUri (lines 46-47)', () => {
  const config = loadConfig(baseEnv({
    CUSTOM_CSS_URL: 'http://[invalid-ipv6-address',
  }));
  const csp1 = contentSecurityPolicy(config, 'https://valid.example.com/logo.png');
  const imgSrc1 = csp1
    .split('; ')
    .find((directive) => directive.startsWith('img-src '))
    ?.slice('img-src '.length)
    .split(' ');
  assert.ok(imgSrc1?.some((source) => source === 'https://valid.example.com'));

  const csp2 = contentSecurityPolicy(config, 'http://[invalid-logo-url');
  assert.ok(!csp2.includes('invalid-logo-url'));
});

// ---------------------------------------------------------------------------
// 10. src/ui/pages.js
// ---------------------------------------------------------------------------

test('ui/pages: describeMethod returns "Already signed in" for non-OTP ACR without upstream label (line 252)', () => {
  const config = loadConfig(baseEnv());
  const ctx = {
    config,
    issuer: 'http://localhost:8787',
    ui: config.ui,
    assets: { js: '/sag.js', css: '/sag.css' },
  };

  const html = continuePage(ctx, {
    tx: 'sealed-tx',
    session: {
      email: 'user@example.org',
      acr: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password', // non-otp acr, no upstreamLabel
    },
    action: '/authorize/continue',
    switchAction: '/authorize/restart',
  });

  assert.match(html, /Already signed in/);
});
