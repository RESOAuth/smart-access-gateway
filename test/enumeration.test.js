// What a sign-in page gives away.
//
// The address screen is the one surface anybody can reach without an account,
// and it answers a question an attacker would like answered: which
// organisations does this deployment serve? Every test here is about the shape
// of the answer rather than the sign-in itself.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, extractField, extractDevCode, authorizeUrl, pkce } from './harness.js';

/** Get to the address screen and submit an address. */
async function submit(sag, email) {
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge });
  const first = await sag.raw(path);
  const tx = extractField(await first.text());
  const res = await sag.postForm('/authorize/email', { tx, email });
  const html = await res.text();
  return { res, html, tx: extractField(html), code: extractDevCode(html) };
}

test('an address the deployment cannot serve looks exactly like one it can', async () => {
  const sag = createInstance({ OTP_ALLOWED_DOMAINS: 'example.org' });

  const served = await submit(sag, 'person@example.org');
  const not = await submit(sag, 'person@elsewhere.test');

  assert.match(served.html, /<h1>Check your email<\/h1>/);
  assert.match(not.html, /<h1>Check your email<\/h1>/, 'the screens must not differ');
  assert.match(not.html, /person@elsewhere\.test/);
  assert.equal(not.res.status, served.res.status);
  // The give-away would be the code itself: none was generated and no mail was
  // sent, but nothing on the page says so.
  assert.ok(served.code, 'the served address really does get a code');
  assert.ok(!not.code, 'the other address must not');
});

test('a decoy screen behaves like a real one all the way to the wrong-code error', async () => {
  const sag = createInstance({ OTP_ALLOWED_DOMAINS: 'example.org' });
  const decoy = await submit(sag, 'person@elsewhere.test');

  const guess = await sag.postForm('/authorize/otp', { tx: decoy.tx, code: '234567892' });
  const html = await guess.text();
  assert.equal(guess.status, 400);
  assert.match(html, /That code is not right/, 'the same wording as a genuine wrong code');

  // Even asking for another one behaves the same way.
  const again = await sag.postForm('/authorize/resend', { tx: decoy.tx });
  const againHtml = await again.text();
  assert.match(againHtml, /<h1>Check your email<\/h1>/);
  assert.ok(!extractDevCode(againHtml));
});

test('an operator can choose to be helpful instead, and is told what it costs', async () => {
  // Kinder for a person who typed their personal address by mistake, and it
  // answers the attacker's question one domain at a time. It is the
  // operator's call, so it is a setting rather than a decision baked in.
  const sag = createInstance({ OTP_ALLOWED_DOMAINS: 'example.org', SIGNIN_UNKNOWN_ADDRESS: 'explain' });
  const not = await submit(sag, 'person@elsewhere.test');
  assert.equal(not.res.status, 400);
  assert.match(not.html, /We cannot sign you in with that address/);
  assert.match(not.html, /does not accept elsewhere\.test addresses/);
});

test('the default is silence', async () => {
  const sag = createInstance({ OTP_ALLOWED_DOMAINS: 'example.org' });
  const not = await submit(sag, 'person@elsewhere.test');
  assert.ok(!/does not accept/.test(not.html), 'nothing is revealed unless it is asked for');
});

test('the decoy screen resends, counts and rate limits exactly like a real one', async () => {
  // Anything that behaved differently here would answer the question the
  // decoy exists not to answer. A resend notice that never appeared, or a
  // send limit that visibly bit one but not the other, is as good as a
  // "no such domain" message.
  const sag = createInstance({ OTP_ALLOWED_DOMAINS: 'example.org', STATE_STORE_BACKEND: 'memory' });

  const served = await submit(sag, 'person@example.org');
  const not = await submit(sag, 'person@elsewhere.test');

  const resend = async (tx) => (await sag.postForm('/authorize/resend', { tx })).text();
  const servedResent = await resend(served.tx);
  const notResent = await resend(not.tx);
  assert.match(notResent, /A new code is on its way/, 'the decoy must resend too');

  // The third send in the window is refused for both, in the same silent
  // way: the ordinary code screen, with nothing on it saying the limit bit.
  const servedThird = await resend(extractField(servedResent));
  const notThird = await resend(extractField(notResent));
  assert.match(servedThird, /<h1>Check your email<\/h1>/);
  assert.match(notThird, /<h1>Check your email<\/h1>/, 'and hit the same limit');
  assert.ok(!/already been sent|too many|today|wait/i.test(servedThird), 'no hint for the real address either');
  assert.ok(!/already been sent|too many|today|wait/i.test(notThird), 'nor for the decoy');
});

test('with email codes switched off entirely there is nothing to be quiet about', async () => {
  // The deployment sends no mail to anybody, so a code screen would conceal
  // nothing and leave the person at a dead end with no route back.
  const sag = createInstance({
    OTP_ENABLED: 'false',
    UPSTREAM_MICROSOFT_EXAMPLEORG_CLIENT_ID: 'example.org:00000000-1111-2222-3333-444444444444',
    UPSTREAM_MICROSOFT_EXAMPLEORG_CLIENT_SECRET: 'shh',
  });
  const not = await submit(sag, 'person@elsewhere.test');
  assert.match(not.html, /We cannot sign you in with that address/);
});
