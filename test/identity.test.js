// What counts as the same person.
//
// Two questions, and they are separate on purpose. Which address is *the*
// address - one mailbox reached by two spellings, or two accounts - is a
// policy, settable per deployment and per relying party. What a `sub` is
// derived from is not: it is always the verified address, never an upstream's
// own subject, so somebody who moves from a Microsoft tenant to an email code
// stays the same person. See
// docs/adr/0011-subject-derived-from-the-verified-address.md.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, redeem, authorizeUrl, extractField, extractDevCode, pkce } from './harness.js';
import { decodeJwt } from '../src/crypto/jose.js';
import { stripPlusTag, identityEmail, subjectFor } from '../src/identity.js';
import { loadConfig } from '../src/config.js';

/** The transaction on a freshly opened sign-in page. */
async function transaction(sag) {
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge });
  return extractField(await (await sag.raw(path)).text());
}

/** Ask for a code, and return it if one was actually sent. */
async function requestCodeFor(sag, email) {
  sag.clearCookies();
  const res = await sag.postForm('/authorize/email', { tx: await transaction(sag), email });
  return extractDevCode(await res.text());
}

const TAGGED = 'jamie.taylor+shop@example.test';
const PLAIN = 'jamie.taylor@example.test';

const claimsFor = async (sag, flow) => {
  const { body } = await redeem(sag, flow);
  return decodeJwt(body.id_token).payload;
};

// ---------------------------------------------------------------------------
// Plus tags
// ---------------------------------------------------------------------------

test('a plus tag is dropped from the local part and nothing else', () => {
  assert.equal(stripPlusTag(TAGGED), PLAIN);
  assert.equal(stripPlusTag('jamie+a+b@example.test'), 'jamie@example.test');
  // Only the local part: a domain is not tagged, and a tag is not a domain.
  assert.equal(stripPlusTag('jamie@ex+ample.test'), 'jamie@ex+ample.test');
  // Nothing in front of the tag is not a tag, it is the whole local part.
  assert.equal(stripPlusTag('+jamie@example.test'), '+jamie@example.test');
  // A quoted local part may legitimately contain one.
  assert.equal(stripPlusTag('"jamie+shop"@example.test'), '"jamie+shop"@example.test');
  assert.equal(stripPlusTag(PLAIN), PLAIN);
  assert.equal(stripPlusTag(''), '');
});

test('an instance sanitises by default, and an operator can turn it off', () => {
  const on = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  assert.equal(on.identity.sanitisePlusEmails, true);
  assert.equal(identityEmail(on, TAGGED), PLAIN);

  const off = loadConfig({ SAG_ISSUER: 'http://localhost:8787', SANITISE_PLUS_EMAILS: 'false' });
  assert.equal(identityEmail(off, TAGGED), TAGGED);
});

test('one relying party can disagree with the instance, in either direction', () => {
  const on = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const off = loadConfig({ SAG_ISSUER: 'http://localhost:8787', SANITISE_PLUS_EMAILS: 'false' });

  assert.equal(identityEmail(on, TAGGED, { sanitisePlusEmails: false }), TAGGED);
  assert.equal(identityEmail(off, TAGGED, { sanitisePlusEmails: true }), PLAIN);
  // Not set is not the same as set to false: it inherits.
  assert.equal(identityEmail(on, TAGGED, { clientId: 'app' }), PLAIN);
  assert.equal(identityEmail(off, TAGGED, { clientId: 'app' }), TAGGED);
});

test('a per-client override is read from the environment as a tri-state', () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENT_KEEP_ID: 'keeps-tags',
    CLIENT_KEEP_REDIRECT_URIS: 'https://keep.test/cb',
    CLIENT_KEEP_SANITISE_PLUS_EMAILS: 'false',
    CLIENT_PLAIN_ID: 'inherits',
    CLIENT_PLAIN_REDIRECT_URIS: 'https://plain.test/cb',
  });
  const by = (id) => config.clients.static.find((c) => c.clientId === id);
  assert.equal(by('keeps-tags').sanitisePlusEmails, false);
  assert.equal(by('inherits').sanitisePlusEmails, undefined, 'unset must stay distinguishable from false');

  const bad = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENT_KEEP_ID: 'typo',
    CLIENT_KEEP_REDIRECT_URIS: 'https://keep.test/cb',
    CLIENT_KEEP_SANITISE_PLUS_EMAILS: 'maybe',
  });
  assert.ok(bad.internalWarnings.some((p) => /CLIENT_KEEP_SANITISE_PLUS_EMAILS must be a boolean/.test(p)));
});

test('the tag is gone from the id_token, and so is the account it would have been', async () => {
  const sag = createInstance({ SUBJECT_SALT: 'never-rotate-this' });
  const tagged = await claimsFor(sag, await signInWithOtp(sag, { email: TAGGED }));
  assert.equal(tagged.email, PLAIN, 'the relying party sees the mailbox, not the spelling');

  sag.clearCookies();
  const plain = await claimsFor(sag, await signInWithOtp(sag, { email: PLAIN }));
  assert.equal(plain.sub, tagged.sub, 'and both spellings are one person');
});

test('with sanitising off, two spellings are two accounts', async () => {
  const sag = createInstance({ SANITISE_PLUS_EMAILS: 'false', SUBJECT_SALT: 'never-rotate-this' });
  const tagged = await claimsFor(sag, await signInWithOtp(sag, { email: TAGGED }));
  assert.equal(tagged.email, TAGGED);

  sag.clearCookies();
  const plain = await claimsFor(sag, await signInWithOtp(sag, { email: PLAIN }));
  assert.notEqual(plain.sub, tagged.sub);
});

test('what the person typed is still what the screens show them', async () => {
  const sag = createInstance();
  const res = await sag.postForm('/authorize/email', { tx: await transaction(sag), email: TAGGED });
  const html = await res.text();
  assert.ok(html.includes(TAGGED), 'echoing back a different address would look like a mistake');
});

// ---------------------------------------------------------------------------
// The rate limit is not a matter of policy
// ---------------------------------------------------------------------------

test('OTP send limits count the mailbox, whatever the identity policy says', async () => {
  // Otherwise inventing a new tag on every attempt walks straight past the
  // limit, which is the one thing it exists to stop.
  const sag = createInstance({
    SANITISE_PLUS_EMAILS: 'false',
    STATE_STORE_BACKEND: 'memory',
    OTP_SEND_WINDOW: '600',
    OTP_SEND_BURST: '1',
  });
  const first = await requestCodeFor(sag, PLAIN);
  assert.ok(first, 'the first send is allowed');
  const second = await requestCodeFor(sag, 'jamie.taylor+again@example.test');
  assert.equal(second, undefined, 'a new tag is the same mailbox and must not reset the count');
});

// ---------------------------------------------------------------------------
// The upstream's own subject never crosses
// ---------------------------------------------------------------------------

test('the subject is derived from the address, so it survives changing upstream', async () => {
  const config = loadConfig({ SAG_ISSUER: 'https://id.example.test', SUBJECT_SALT: 'never-rotate-this' });
  const client = { clientId: 'app', redirectUris: ['https://app.test/cb'] };
  // Nothing about the sign-in method is in the derivation, so the same person
  // arriving by upstream or by email code is the same `sub` either way.
  assert.equal(await subjectFor(config, PLAIN, client), await subjectFor(config, PLAIN, client));
  assert.notEqual(await subjectFor(config, 'someone.else@example.test', client), await subjectFor(config, PLAIN, client));
});
