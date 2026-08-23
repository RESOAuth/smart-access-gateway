// Rotating the master secret.
//
// SAG_SECRET protects sessions, transactions, codes and access tokens. Rotating
// it must not sign everybody out, so SAG_SECRET_PREVIOUS is accepted for
// opening tokens while only the current secret is used for sealing them. These
// tests hold that to account, and equally check that dropping the old secret
// really does invalidate what it sealed - otherwise "rotated" would not mean
// anything.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, redeem, pkce, authorizeUrl, extractField } from './harness.js';
import { seal, unseal, SealError } from '../src/crypto/secrets.js';

const OLD = 'old-master-secret-'.repeat(3);
const NEW = 'new-master-secret-'.repeat(3);
const EMAIL = 'person@example.org';

/** Sign in under one secret and return the session cookie. */
async function sessionSealedWith(secret) {
  const sag = createInstance({ SAG_SECRET: secret });
  await signInWithOtp(sag, { email: EMAIL });
  const entries = [...sag.cookies];
  assert.equal(entries.length, 1, 'expected exactly one session cookie');
  return entries[0];
}

/** Ask prompt=none, which can only succeed from a readable session. */
async function silentSignIn(sag) {
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'none' });
  const res = await sag.raw(path);
  assert.equal(res.status, 303);
  const location = new URL(res.headers.get('location'));
  return { code: location.searchParams.get('code'), error: location.searchParams.get('error') };
}

test('a session survives a rotation while the previous secret is still accepted', async () => {
  const cookie = await sessionSealedWith(OLD);

  const rotated = createInstance({ SAG_SECRET: NEW, SAG_SECRET_PREVIOUS: OLD });
  rotated.cookies.set(cookie[0], cookie[1]);

  const { code, error } = await silentSignIn(rotated);
  assert.ok(code, 'the session should still be readable, got error=' + error);
});

test('dropping the previous secret does invalidate what it sealed', async () => {
  const cookie = await sessionSealedWith(OLD);

  const clean = createInstance({ SAG_SECRET: NEW });
  clean.cookies.set(cookie[0], cookie[1]);

  const { code, error } = await silentSignIn(clean);
  assert.equal(code, null, 'a session sealed under a retired secret must not be honoured');
  assert.equal(error, 'login_required');
});

test('a rotated instance re-seals with the new secret, not the old one', async () => {
  const cookie = await sessionSealedWith(OLD);

  // Use the session on the rotated instance, which refreshes the cookie.
  const rotated = createInstance({ SAG_SECRET: NEW, SAG_SECRET_PREVIOUS: OLD });
  rotated.cookies.set(cookie[0], cookie[1]);
  await silentSignIn(rotated);
  const refreshed = [...rotated.cookies][0];
  assert.notEqual(refreshed[1], cookie[1], 'the cookie should have been rewritten');

  // The refreshed cookie must now work on an instance that has forgotten the
  // old secret entirely - which is what makes the rotation completable.
  const finished = createInstance({ SAG_SECRET: NEW });
  finished.cookies.set(refreshed[0], refreshed[1]);
  const { code } = await silentSignIn(finished);
  assert.ok(code, 'once re-sealed, the session no longer needs the old secret');
});

test('a transaction started before a rotation can still be completed', async () => {
  // Somebody halfway through typing their code should not be thrown out
  // because a deployment happened.
  const before = createInstance({ SAG_SECRET: OLD });
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge });
  const first = await before.raw(path);
  const tx = extractField(await first.text());

  const rotated = createInstance({ SAG_SECRET: NEW, SAG_SECRET_PREVIOUS: OLD });
  const otp = await rotated.postForm('/authorize/email', { tx, email: EMAIL });
  const otpHtml = await otp.text();
  assert.match(otpHtml, /Check your email/, 'the in-flight transaction should still open');

  const done = await rotated.postForm('/authorize/otp', {
    tx: extractField(otpHtml),
    code: otpHtml.match(/<code>([0-9A-Z]+)<\/code>/)[1],
  });
  assert.equal(done.status, 303, 'and the flow should complete');
});

test('a code issued before a rotation can still be redeemed', async () => {
  const before = createInstance({ SAG_SECRET: OLD });
  const flow = await signInWithOtp(before, { email: EMAIL });

  const rotated = createInstance({ SAG_SECRET: NEW, SAG_SECRET_PREVIOUS: OLD });
  const { res, body } = await redeem(rotated, flow);
  assert.equal(res.status, 200, JSON.stringify(body));
});

test('sealing always uses the current secret, never a previous one', async () => {
  // The ordering rule: the first secret in the list seals, all of them open.
  // Getting this backwards would mean a rotation never actually completed.
  const sealed = await seal(NEW, 'session', { hello: 'world' });
  assert.deepEqual(await unseal([NEW, OLD], 'session', sealed), { hello: 'world' });
  await assert.rejects(() => unseal([OLD], 'session', sealed), SealError);
});

test('a token cannot be replayed into a different purpose after a rotation', async () => {
  // The purpose is authenticated as additional data, and that must not become
  // a weaker guarantee just because two secrets are in play.
  const sealed = await seal(OLD, 'tx', { hello: 'world' });
  await assert.rejects(() => unseal([NEW, OLD], 'session', sealed), SealError);
  await assert.rejects(() => unseal([NEW, OLD], 'code', sealed), SealError);
  assert.deepEqual(await unseal([NEW, OLD], 'tx', sealed), { hello: 'world' });
});
