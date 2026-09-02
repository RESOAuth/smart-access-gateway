// CORS on /token and /userinfo: the two routes a browser-based relying party
// calls directly with fetch(), rather than by navigating there. On for every
// origin by default, so a public client works with no CORS configuration at
// all; CORS_ALLOWED_ORIGINS narrows that and CORS_ENABLED=false removes it.
// Everywhere else stays exactly as uncooperative with cross-origin JavaScript
// as before.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, redeem, DEV_CLIENT, DEV_REDIRECT } from './harness.js';
import { loadConfig } from '../src/config.js';

const EMAIL = 'someone@example.org';
const APP_ORIGIN = 'https://app.example.com';
const SECRET = 'test-secret-'.repeat(4);

async function signIn(sag) {
  return signInWithOtp(sag, { email: EMAIL });
}

// ---------------------------------------------------------------------------
// Configuration parsing
// ---------------------------------------------------------------------------

test('CORS is on for every origin by default', () => {
  const config = loadConfig({ SAG_ISSUER: 'https://auth.example.com', SAG_SECRET: SECRET });
  assert.equal(config.cors.enabled, true);
  assert.deepEqual(config.cors.allowedOrigins, ['*']);
});

test('registering a static client does not narrow the default to that client', () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: SECRET,
    CLIENT_APP_ID: 'app-client',
    CLIENT_APP_REDIRECT_URIS: APP_ORIGIN + '/callback',
  });
  assert.deepEqual(config.cors.allowedOrigins, ['*']);
});

test("a static client's own redirect URI origin survives a narrowing to somebody else", () => {
  const OTHER = 'https://other.example.com';
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: SECRET,
    CLIENT_APP_ID: 'app-client',
    // Two redirect URIs on the same origin still trust that origin once.
    CLIENT_APP_REDIRECT_URIS: [APP_ORIGIN + '/callback', APP_ORIGIN + '/other-callback'].join(','),
    CORS_ALLOWED_ORIGINS: OTHER,
  });
  assert.deepEqual(config.cors.allowedOrigins.sort(), [APP_ORIGIN, OTHER].sort());
});

test('CORS_ENABLED=false turns it off entirely, including auto-derived origins', () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: SECRET,
    CLIENT_APP_ID: 'app-client',
    CLIENT_APP_REDIRECT_URIS: APP_ORIGIN + '/callback',
    CORS_ENABLED: 'false',
  });
  assert.equal(config.cors.enabled, false);
  assert.deepEqual(config.cors.allowedOrigins, []);
});

test('a malformed or path-carrying CORS_ALLOWED_ORIGINS entry is dropped, not fatal', () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: SECRET,
    CORS_ALLOWED_ORIGINS: [APP_ORIGIN, 'not-a-url', 'https://other.example.com/some/path'].join(','),
  });
  assert.deepEqual(config.cors.allowedOrigins, [APP_ORIGIN]);
  assert.ok(config.internalWarnings.some((w) => w.includes('not-a-url')));
  assert.ok(config.internalWarnings.some((w) => /has no path, query or fragment/.test(w)));
});

test('a plain http CORS_ALLOWED_ORIGINS entry is refused outside development', () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: SECRET,
    CORS_ALLOWED_ORIGINS: 'http://app.example.com',
  });
  assert.deepEqual(config.cors.allowedOrigins, []);
  assert.ok(config.internalWarnings.some((w) => /must be an https origin/.test(w)));
});

// ---------------------------------------------------------------------------
// /token: works out of the box for a registered relying party
// ---------------------------------------------------------------------------

const SPA_ORIGIN = 'http://127.0.0.1:9999';
const SPA_REDIRECT = SPA_ORIGIN + '/callback';
const SPA_ENV = { CLIENT_SPA_ID: 'spa-client', CLIENT_SPA_REDIRECT_URIS: SPA_REDIRECT };

async function signInSpa(sag) {
  return signInWithOtp(sag, { email: EMAIL, authorize: { clientId: 'spa-client', redirectUri: SPA_REDIRECT } });
}

test("a public client's own page gets CORS with no CORS_ALLOWED_ORIGINS set at all", async () => {
  const sag = createInstance(SPA_ENV);
  const flow = await signInSpa(sag);

  const res = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: SPA_ORIGIN },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: SPA_REDIRECT,
      client_id: 'spa-client',
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');

  const preflight = await sag.raw('/token', { method: 'OPTIONS', headers: { origin: SPA_ORIGIN } });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('access-control-allow-origin'), '*');
});

test('CORS_ENABLED=false overrides the auto-derived origin too', async () => {
  const sag = createInstance({ ...SPA_ENV, CORS_ENABLED: 'false' });
  const flow = await signInSpa(sag);

  const preflight = await sag.raw('/token', { method: 'OPTIONS', headers: { origin: SPA_ORIGIN } });
  assert.equal(preflight.headers.get('access-control-allow-origin'), null);

  const res = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: SPA_ORIGIN },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: SPA_REDIRECT,
      client_id: 'spa-client',
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('an origin nobody registered is allowed too, because the default is every origin', async () => {
  // The case the default exists for: a CIMD client, or one out of a client
  // store, whose origin was never in the start-up configuration to derive.
  const sag = createInstance();
  const flow = await signIn(sag);
  const res = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: APP_ORIGIN },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      client_id: DEV_CLIENT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  assert.equal(res.headers.get('vary'), null);
});

test('narrowing with CORS_ALLOWED_ORIGINS shuts an unnamed origin out again', async () => {
  const sag = createInstance({ CORS_ALLOWED_ORIGINS: APP_ORIGIN });
  const flow = await signIn(sag);
  const res = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example.com' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      client_id: DEV_CLIENT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('a preflight from an origin not on the list gets no allow-origin back', async () => {
  const sag = createInstance({ CORS_ALLOWED_ORIGINS: APP_ORIGIN });
  const res = await sag.raw('/token', { method: 'OPTIONS', headers: { origin: 'https://evil.example.com' } });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('a preflight lists the token endpoint headers and methods', async () => {
  const sag = createInstance({ CORS_ALLOWED_ORIGINS: APP_ORIGIN });
  const res = await sag.raw('/token', {
    method: 'OPTIONS',
    headers: { origin: APP_ORIGIN, 'access-control-request-method': 'POST' },
  });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('access-control-allow-origin'), APP_ORIGIN);
  assert.match(res.headers.get('access-control-allow-methods'), /POST/);
  assert.match(res.headers.get('access-control-allow-headers'), /authorization/);
  assert.equal(res.headers.get('vary'), 'origin');
});

test('an explicitly allowed origin gets access-control-allow-origin on both success and refusal', async () => {
  const sag = createInstance({ CORS_ALLOWED_ORIGINS: APP_ORIGIN });
  const flow = await signIn(sag);

  const ok = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: APP_ORIGIN },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      client_id: DEV_CLIENT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('access-control-allow-origin'), APP_ORIGIN);
  assert.equal(ok.headers.get('vary'), 'origin');

  // A refusal must be just as readable to the relying party's own JavaScript
  // as a success was - the wrong PKCE verifier is refused whether or not a
  // state store is configured, unlike replaying the same code.
  const wrong = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: APP_ORIGIN },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      client_id: DEV_CLIENT,
      code_verifier: 'not-the-right-verifier',
    }).toString(),
  });
  assert.equal(wrong.status, 400);
  assert.equal((await wrong.json()).error, 'invalid_grant');
  assert.equal(wrong.headers.get('access-control-allow-origin'), APP_ORIGIN);
});

test('a token exchange with no Origin header carries no CORS response headers', async () => {
  const sag = createInstance({ CORS_ALLOWED_ORIGINS: APP_ORIGIN });
  const flow = await signIn(sag);
  // A server-to-server redemption, as harness.redeem() sends it: no browser
  // involved, so nothing sends an Origin header to reflect back.
  const { res } = await redeem(sag, flow);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('CORS_ALLOWED_ORIGINS=* allows every origin, without Vary', async () => {
  const sag = createInstance({ CORS_ALLOWED_ORIGINS: '*' });
  const flow = await signIn(sag);
  const res = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://anywhere.example.com' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      client_id: DEV_CLIENT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  assert.equal(res.headers.get('vary'), null);
});

// ---------------------------------------------------------------------------
// /userinfo
// ---------------------------------------------------------------------------

test('/userinfo carries CORS headers on both a valid and an invalid bearer token', async () => {
  const sag = createInstance({ CORS_ALLOWED_ORIGINS: APP_ORIGIN });
  const flow = await signIn(sag);
  const { body } = await redeem(sag, flow);

  const ok = await sag.raw('/userinfo', {
    headers: { authorization: 'Bearer ' + body.access_token, origin: APP_ORIGIN },
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('access-control-allow-origin'), APP_ORIGIN);
  assert.equal(ok.headers.get('access-control-expose-headers'), 'www-authenticate');

  const bad = await sag.raw('/userinfo', { headers: { authorization: 'Bearer nonsense', origin: APP_ORIGIN } });
  assert.equal(bad.status, 401);
  assert.equal(bad.headers.get('access-control-allow-origin'), APP_ORIGIN);
});

// ---------------------------------------------------------------------------
// Everywhere else
// ---------------------------------------------------------------------------

test('the hosted sign-in pages never carry CORS headers, even with a configured origin and an Origin header', async () => {
  const sag = createInstance({ CORS_ALLOWED_ORIGINS: APP_ORIGIN });
  const res = await sag.raw('/authorize?' + new URLSearchParams({ client_id: 'no-such-client' }), {
    headers: { origin: APP_ORIGIN },
  });
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});
