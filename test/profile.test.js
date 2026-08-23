// Profile claims: what crosses, and what is guessed.
//
// Two separate promises are under test. The relay must be a strict allow list,
// because an upstream that could put arbitrary claims into a relying party's
// id_token would be a way to attack the relying party through SAG. And the
// guess - a display name derived from an email address, for the email code path
// where there is no upstream at all - must be conservative and must be labelled
// as a guess, because `name` is supposed to mean the person's name.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, redeem, pkce, authorizeUrl } from './harness.js';
import { nameFromEmail, initialsFor, initialsAvatar, relayedClaims, inferredClaims, outboundClaims } from '../src/profile.js';
import { loadConfig } from '../src/config.js';
import { decodeJwt } from '../src/crypto/jose.js';

const config = (env = {}) => loadConfig({ SAG_ISSUER: 'http://localhost:8787', ...env });

/** Sign in and redeem, returning the id_token claims and the token response. */
async function signInAndRedeem(sag, { email, scope }) {
  const flow = await signInWithOtp(sag, { email, authorize: scope ? { scope } : {} });
  const { res, body } = await redeem(sag, flow);
  if (res.status !== 200) throw new Error('token endpoint said ' + res.status + ': ' + JSON.stringify(body));
  return { claims: decodeJwt(body.id_token).payload, tokens: body };
}

/** The screen a relying party gets when it asks for the account to be confirmed. */
async function continueScreen(sag) {
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'consent' });
  return (await sag.raw(path)).text();
}

// ---------------------------------------------------------------------------
// Guessing a name
// ---------------------------------------------------------------------------

test('the shapes a name actually comes in are recognised', () => {
  assert.equal(nameFromEmail('jamie.taylor@example.org'), 'Jamie Taylor');
  assert.equal(nameFromEmail('jamie_taylor@example.org'), 'Jamie Taylor');
  assert.equal(nameFromEmail('jamie-taylor@example.org'), 'Jamie Taylor');
  assert.equal(nameFromEmail('JAMIE.TAYLOR@example.org'), 'Jamie Taylor');
  assert.equal(nameFromEmail('jamie@example.org'), 'Jamie');
  // A single initial is expanded rather than dropped, which is how plenty of
  // organisations issue addresses.
  assert.equal(nameFromEmail('j.taylor@example.org'), 'J. Taylor');
  // A plus tag is somebody's own filing system, not part of their name.
  assert.equal(nameFromEmail('jamie.taylor+shopping@example.org'), 'Jamie Taylor');

  // A separator is all there is to go on. Splitting on a case boundary would
  // read `jamieTaylor` as two words, but the address is folded to lower case by
  // normaliseEmail long before a guess is made, so there is never a case
  // boundary left to find and one word is the only honest reading.
  assert.equal(nameFromEmail('jamietaylor@example.org'), 'Jamietaylor');
  assert.equal(nameFromEmail('jamieTaylor@example.org'), 'Jamietaylor');
});

test('anything that is not plausibly a name is left alone', () => {
  // The case that matters: a wrong guess is worse than no guess, so each of
  // these has to produce nothing rather than something nearly right.
  for (const local of [
    '12345',            // an account reference
    'a1b2c3d4e5f6',     // a machine identifier
    '3f2504e0-4f89-11d3-9a0c-0305e82c3301',
    'jamie2',           // a disambiguator, or a birth year, no way to tell
    'admin',            // a role, not a person
    'no-reply',
    'support',
    'x',                // too short to be anything
    'o',
    'a.b.c.d.e',        // too many parts to be a name
    'jamie.taylor!',     // not letters
  ]) {
    assert.equal(nameFromEmail(local + '@example.org'), undefined, local + ' should not produce a name');
  }
  assert.equal(nameFromEmail(''), undefined);
  assert.equal(nameFromEmail(undefined), undefined);
  assert.equal(nameFromEmail('a'.repeat(60) + '@example.org'), undefined);
});

test('initials fall back through name, then address, then nothing', () => {
  assert.equal(initialsFor({ name: 'Jamie Taylor' }), 'JT');
  assert.equal(initialsFor({ name: 'Jamie' }), 'JA');
  assert.equal(initialsFor({ email: 'jamie.taylor@example.org' }), 'JT');
  assert.equal(initialsFor({ email: 'admin@example.org' }), 'AD');
  assert.equal(initialsFor({ email: '12345@example.org' }), '?');
});

test('the avatar is a self-contained data URI and asks nobody anything', () => {
  const avatar = initialsAvatar({ name: 'Jamie Taylor', email: 'jamie.taylor@example.org' });
  assert.match(avatar, /^data:image\/svg\+xml,/);
  const svg = decodeURIComponent(avatar.slice('data:image/svg+xml,'.length));
  assert.match(svg, /<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, />JT</);
  // No request to anybody: an avatar service would be handed the address, or a
  // hash of it, and with it the fact of every sign-in on the deployment.
  assert.ok(!/https?:\/\/(?!www\.w3\.org)/.test(svg), 'nothing may be fetched');
  assert.ok(avatar.length < 700, 'it travels in an id_token, so it has to be small');
  // Stable for the same person, so the avatar does not change between visits.
  assert.equal(avatar, initialsAvatar({ name: 'Jamie Taylor', email: 'jamie.taylor@example.org' }));
});

// ---------------------------------------------------------------------------
// Relaying from an upstream
// ---------------------------------------------------------------------------

test('only allow-listed claims cross from an upstream', () => {
  const relayed = relayedClaims(config(), {
    name: 'Jamie Taylor',
    given_name: 'Jamie',
    picture: 'https://cdn.example.test/o.jpg',
    email: 'someone.else@evil.test',
    sub: 'upstream-subject',
    admin: true,
    'https://claims.example/roles': ['owner'],
  });
  assert.deepEqual(relayed, {
    name: 'Jamie Taylor',
    given_name: 'Jamie',
    picture: 'https://cdn.example.test/o.jpg',
  });
  // The dangerous ones by name: an upstream must not be able to restate the
  // subject or the address SAG has already decided on.
  assert.equal(relayed.sub, undefined);
  assert.equal(relayed.email, undefined);
});

test('a picture that is not an https URL is dropped', () => {
  for (const picture of ['javascript:alert(1)', 'data:image/svg+xml,<svg/>', 'http://cdn.test/a.jpg', '/relative.jpg']) {
    const relayed = relayedClaims(config(), { name: 'Jamie', picture });
    assert.equal(relayed.picture, undefined, picture + ' must not be relayed');
    assert.equal(relayed.name, 'Jamie', 'the rest of the claims still come through');
  }
});

test('an absurdly long picture URL is dropped rather than truncated', () => {
  // Truncating a URL produces a shorter URL that is not the same URL, which a
  // relying party would then put in an <img> and get a 404 from. Text can be
  // capped; an address cannot.
  const long = 'https://cdn.example.test/' + 'a'.repeat(600) + '.jpg';
  const relayed = relayedClaims(config(), { name: 'Jamie Taylor', picture: long });
  assert.equal(relayed.picture, undefined);
  assert.equal(relayed.name, 'Jamie Taylor');

  const longName = relayedClaims(config(), { name: 'O'.repeat(900) });
  assert.equal(longName.name.length, 512, 'a name is capped, because it is only text');
});

test('an operator can narrow what crosses, and switch pictures off', () => {
  const narrowed = relayedClaims(config({ PROFILE_CLAIMS: 'name' }), {
    name: 'Jamie Taylor',
    given_name: 'Jamie',
    picture: 'https://cdn.example.test/o.jpg',
  });
  assert.deepEqual(narrowed, { name: 'Jamie Taylor' });

  const noPicture = relayedClaims(config({ PROFILE_PICTURE: 'false' }), {
    name: 'Jamie Taylor',
    picture: 'https://cdn.example.test/o.jpg',
  });
  assert.deepEqual(noPicture, { name: 'Jamie Taylor' });
});

test('the upstream acr is kept so a relying party can reason about step-up', () => {
  const relayed = relayedClaims(config(), { name: 'Jamie' }, 'urn:microsoft:mfa');
  assert.equal(relayed.upstream_acr, 'urn:microsoft:mfa');
});

// ---------------------------------------------------------------------------
// Inference, off by default
// ---------------------------------------------------------------------------

test('nothing is guessed unless the operator asked for it', () => {
  assert.equal(inferredClaims(config(), 'jamie.taylor@example.org'), undefined);
});

test('a guessed name is emitted as one', () => {
  const held = inferredClaims(config({ PROFILE_NAME_FROM_EMAIL: 'infer' }), 'jamie.taylor@example.org');
  assert.equal(held.name, 'Jamie Taylor');
  assert.equal(held.name_inferred, true);
  assert.equal(held.picture, undefined, 'the avatar is a separate decision');

  // On the way out, the flag becomes a namespaced claim: there is no standard
  // way to say "this is our best guess", and pretending there is would be the
  // thing this whole arrangement is meant to avoid.
  const out = outboundClaims(config({ PROFILE_NAME_FROM_EMAIL: 'infer' }), held);
  assert.equal(out.name, 'Jamie Taylor');
  assert.equal(out['urn:sag:name_inferred'], true);
  assert.equal(out.name_inferred, undefined, 'the internal flag must not leak as a claim');
});

test('the avatar is only drawn once there is a name to draw from', () => {
  const env = { PROFILE_NAME_FROM_EMAIL: 'infer', PROFILE_AVATAR_FALLBACK: 'initials' };
  const named = inferredClaims(config(env), 'jamie.taylor@example.org');
  assert.match(named.picture, /^data:image\/svg\+xml,/);

  // An opaque local part yields no name, so initials from it would be noise.
  assert.equal(inferredClaims(config(env), 'a1b2c3d4e5f6@example.org'), undefined);
});

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

test('a guessed name reaches the id_token and userinfo, flagged', async () => {
  const sag = createInstance({ PROFILE_NAME_FROM_EMAIL: 'infer', PROFILE_AVATAR_FALLBACK: 'initials' });
  const { claims, tokens } = await signInAndRedeem(sag, { email: 'jamie.taylor@example.org', scope: 'openid email profile' });

  assert.equal(claims.name, 'Jamie Taylor');
  assert.equal(claims['urn:sag:name_inferred'], true);
  assert.match(claims.picture, /^data:image\/svg\+xml,/);

  const { body: userinfo } = await sag.json('/userinfo', {
    headers: { authorization: 'Bearer ' + tokens.access_token },
  });
  assert.equal(userinfo.name, 'Jamie Taylor');
  assert.equal(userinfo['urn:sag:name_inferred'], true);
});

test('without the profile scope a name is never sent, guessed or not', async () => {
  const sag = createInstance({ PROFILE_NAME_FROM_EMAIL: 'infer' });
  const { claims, tokens } = await signInAndRedeem(sag, { email: 'jamie.taylor@example.org', scope: 'openid email' });
  assert.equal(claims.name, undefined);
  assert.equal(claims['urn:sag:name_inferred'], undefined);

  const { body: userinfo } = await sag.json('/userinfo', {
    headers: { authorization: 'Bearer ' + tokens.access_token },
  });
  assert.equal(userinfo.name, undefined);
  assert.equal(userinfo.email, 'jamie.taylor@example.org', 'the email scope is unaffected');
});

test('the continue screen shows the name and avatar it holds', async () => {
  const sag = createInstance({ PROFILE_NAME_FROM_EMAIL: 'infer', PROFILE_AVATAR_FALLBACK: 'initials' });
  await signInWithOtp(sag, { email: 'jamie.taylor@example.org' });
  const html = await continueScreen(sag);

  assert.match(html, /<strong>Jamie Taylor<\/strong>/);
  assert.match(html, /jamie.taylor@example.org/, 'the address is still shown, because that is what is asserted');
  assert.match(html, /<img class="avatar" src="data:image\/svg\+xml,[^"]+" alt=""/);
  assert.match(html, /Continue as Jamie Taylor/);
});

test('an operator can keep the claims but keep them off the screen', async () => {
  const sag = createInstance({
    PROFILE_NAME_FROM_EMAIL: 'infer',
    PROFILE_AVATAR_FALLBACK: 'initials',
    PROFILE_SHOW_ON_SCREEN: 'false',
  });
  const { claims } = await signInAndRedeem(sag, { email: 'jamie.taylor@example.org', scope: 'openid email profile' });
  assert.equal(claims.name, 'Jamie Taylor', 'the relying party still gets it');

  const html = await continueScreen(sag);
  assert.ok(!html.includes('Jamie Taylor'), 'but the screen shows only the address');
  assert.ok(!html.includes('class="avatar"'));
  assert.match(html, /jamie.taylor@example.org/);
});
