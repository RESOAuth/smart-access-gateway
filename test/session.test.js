// The sign-in session: the two lifetimes that bound it, and the fact that
// answering a request is what keeps one alive.
//
// No test waits on real time. A session with a deadline part way through its
// window is built and sealed directly, then handed to a running instance in a
// cookie, which is the same thing the browser would present after some hours.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { newSession, touch, sealSession, cookieNameFor } from '../src/session.js';
import { nowSeconds } from '../src/util/bytes.js';
import { createInstance, authorizeUrl, pkce, DEV_CLIENT } from './harness.js';

const SECRET = 'test-secret-'.repeat(4);
const ISSUER = 'http://localhost:8787';

const configWith = (overrides = {}) => loadConfig({ SAG_ISSUER: ISSUER, SAG_SECRET: SECRET, ...overrides });

/** The Max-Age a response's session cookie was set with. */
function sessionCookieMaxAge(response, name) {
  for (const raw of response.headers.getSetCookie?.() ?? []) {
    if (!raw.startsWith(name + '=')) continue;
    const m = raw.match(/max-age=(\d+)/i);
    if (m) return Number(m[1]);
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// The two lifetimes
// ---------------------------------------------------------------------------

test('touch moves the idle deadline forward', () => {
  const config = configWith({ SESSION_TTL: '3600', SESSION_MAX_LIFETIME: '86400' });
  const session = newSession(config, { email: 'jamie.taylor@example.com', acr: 'urn:sag:acr:email-otp' });
  const stale = { ...session, exp: nowSeconds() + 60 };

  const touched = touch(config, stale);
  assert.ok(touched.exp > stale.exp, 'using a session must extend its idle window');
  assert.equal(touched.exp, nowSeconds() + 3600);
});

test('touch never pushes the idle deadline past the absolute cap', () => {
  const config = configWith({ SESSION_TTL: '3600', SESSION_MAX_LIFETIME: '86400' });
  const session = newSession(config, { email: 'jamie.taylor@example.com', acr: 'urn:sag:acr:email-otp' });
  // Nearly at the absolute cap, which never moves however much the session is
  // used - this is what stops one being kept alive indefinitely.
  const nearlyOver = { ...session, exp: nowSeconds() + 60, abs: nowSeconds() + 120 };

  assert.equal(touch(config, nearlyOver).exp, nearlyOver.abs);
});

// ---------------------------------------------------------------------------
// Through a running instance
// ---------------------------------------------------------------------------

/** Present a session that is part way through its idle window. */
async function withPlantedSession(env, { idleLeftSeconds }) {
  const instance = createInstance(env);
  const config = loadConfig(instance.env);
  const session = newSession(config, {
    email: 'jamie.taylor@example.com',
    acr: 'urn:sag:acr:email-otp',
    amr: ['otp'],
  });
  const planted = { ...session, exp: nowSeconds() + idleLeftSeconds };
  const name = await cookieNameFor(config, undefined);
  instance.cookies.set(name, encodeURIComponent(await sealSession(config, planted)));
  return { instance, name, planted };
}

test('answering a request rolls the idle timeout forward', async () => {
  const { instance, name } = await withPlantedSession(
    { SESSION_TTL: '3600', SESSION_MAX_LIFETIME: '86400' },
    { idleLeftSeconds: 60 },
  );

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'none' });
  const res = await instance.raw(path);

  assert.equal(res.status, 303, 'the planted session should answer this silently');
  assert.ok(
    new URL(res.headers.get('location')).searchParams.has('code'),
    'and it should produce an authorization code',
  );
  const maxAge = sessionCookieMaxAge(res, name);
  assert.ok(maxAge > 3000, 'the refreshed cookie should carry a full idle window, not the 60 seconds left: ' + maxAge);
});

test('using a session does not extend it past its absolute lifetime', async () => {
  // The absolute cap is the shorter of the two here, so the rolled-forward
  // idle deadline has to be clamped to it.
  const { instance, name, planted } = await withPlantedSession(
    { SESSION_TTL: '3600', SESSION_MAX_LIFETIME: '3600' },
    { idleLeftSeconds: 60 },
  );

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'none' });
  const res = await instance.raw(path);

  assert.equal(res.status, 303);
  const maxAge = sessionCookieMaxAge(res, name);
  assert.ok(maxAge <= planted.abs - nowSeconds(), 'the absolute cap must still bound it: ' + maxAge);
});

test('a session past its absolute lifetime is not answered from at all', async () => {
  const { instance } = await withPlantedSession(
    { SESSION_TTL: '3600', SESSION_MAX_LIFETIME: '3600' },
    { idleLeftSeconds: 60 },
  );
  const config = loadConfig(instance.env);
  const name = await cookieNameFor(config, undefined);
  const session = newSession(config, { email: 'jamie.taylor@example.com', acr: 'urn:sag:acr:email-otp' });
  instance.cookies.set(
    name,
    encodeURIComponent(await sealSession(config, { ...session, abs: nowSeconds() - 1 })),
  );

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, clientId: DEV_CLIENT, prompt: 'none' });
  const res = await instance.raw(path);

  assert.equal(res.status, 303);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'login_required');
});
