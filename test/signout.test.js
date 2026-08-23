// Signing out, and who gets asked first.
//
// With a shared session one relying party asking to sign out is asking on
// everybody's behalf, so the default is to say so and let the person decide.
// An application that owns its own sign-out button has already asked, and can
// say so; one that links here from a menu has not.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, extractField, DEV_CLIENT, DEV_REDIRECT } from './harness.js';
import { loadConfig } from '../src/config.js';

const EMAIL = 'person@example.org';

test('a shared session is confirmed before it is ended', async () => {
  const sag = createInstance();
  await signInWithOtp(sag, { email: EMAIL });

  const confirm = await sag.raw('/logout');
  const html = await confirm.text();
  assert.match(html, /<h1>Sign out\?<\/h1>/);
  assert.match(html, /every application that uses this sign-in service/);
  assert.match(html, new RegExp(EMAIL), 'which account is ending must be visible');

  const done = await sag.postForm('/logout', { lt: extractField(html, 'lt') });
  assert.match(await done.text(), /You are signed out/);
});

test('a per-RP session ends without an interstitial, because only one is affected', async () => {
  const sag = createInstance({ SESSION_SCOPE: 'rp' });
  await signInWithOtp(sag, { email: EMAIL });
  const res = await sag.raw('/logout?client_id=' + DEV_CLIENT);
  assert.match(await res.text(), /You are signed out/, 'nothing to warn anybody about');
});

test('an instance can always ask, or never ask', async () => {
  const always = createInstance({ SESSION_SCOPE: 'rp', LOGOUT_CONFIRM: 'always' });
  await signInWithOtp(always, { email: EMAIL });
  const asked = await always.raw('/logout?client_id=' + DEV_CLIENT);
  const askedHtml = await asked.text();
  assert.match(askedHtml, /<h1>Sign out\?<\/h1>/);
  assert.match(askedHtml, /end your session for/, 'and it must not claim more than it will do');

  const never = createInstance({ LOGOUT_CONFIRM: 'never' });
  await signInWithOtp(never, { email: EMAIL });
  const straight = await never.raw('/logout');
  assert.match(await straight.text(), /You are signed out/);
});

test('a relying party can override the instance default', async () => {
  // The application already asked "are you sure?" in its own interface, so a
  // second page asking the same thing is noise.
  const sag = createInstance({
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_APP_POST_LOGOUT_REDIRECT_URIS: 'http://127.0.0.1:8788/',
    CLIENT_APP_LOGOUT_CONFIRM: 'never',
  });
  await signInWithOtp(sag, { email: EMAIL });

  const res = await sag.raw(
    '/logout?client_id=' + DEV_CLIENT + '&post_logout_redirect_uri=' + encodeURIComponent('http://127.0.0.1:8788/'),
  );
  assert.equal(res.status, 303, 'straight back to the application');
  assert.equal(res.headers.get('location'), 'http://127.0.0.1:8788/');
});

test('an override cannot end more than the person was told about', async () => {
  // "never" skips the question; it does not widen what is cleared. A shared
  // session still only ends because the instance is configured for one.
  const sag = createInstance({
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_APP_LOGOUT_CONFIRM: 'never',
  });
  await signInWithOtp(sag, { email: EMAIL });
  const res = await sag.raw('/logout?client_id=' + DEV_CLIENT);
  assert.match(await res.text(), /You are signed out/);
  assert.equal(sag.cookies.size, 0, 'the shared session really is gone');
});

test('a per-client override that is not one of the three values is reported', async () => {
  // Silently ignoring a typo would leave an interstitial the operator thought
  // they had turned off, and nothing to tell them why.
  const env = {
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_APP_LOGOUT_CONFIRM: 'false',
  };
  const sag = createInstance(env);
  // In the start-up banner and the logs, not in /healthz: the message names a
  // relying party, and /healthz does not describe who is configured here.
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787', ...env });
  assert.ok(
    config.internalWarnings.some((w) => /CLIENT_APP_LOGOUT_CONFIRM must be auto, always or never/.test(w)),
    'the operator has to be able to find out why: ' + JSON.stringify(config.internalWarnings),
  );
  const { body } = await sag.json('/healthz');
  assert.ok(!JSON.stringify(body.warnings).includes('CLIENT_APP'), 'and a stranger must not be told a client slug');

  // And the instance default still applies, rather than something invented.
  await signInWithOtp(sag, { email: EMAIL });
  const res = await sag.raw('/logout?client_id=' + DEV_CLIENT);
  assert.match(await res.text(), /<h1>Sign out\?<\/h1>/);
});
