import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, pkce, authorizeUrl, extractField, extractDevCode } from './harness.js';
import { REMEMBER_ME_COOKIE, REMEMBER_ME_TTL_SECONDS } from '../src/remember-me.js';

const EMAIL = 'person@example.org';

async function begin(sag, extra = {}) {
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, ...extra });
  const res = await sag.raw(path);
  return { res, html: await res.text() };
}

async function authenticate(sag, { tx, email = EMAIL, remember = true }) {
  const fields = { tx, email };
  if (remember) fields.remember_me = '1';
  const otp = await sag.postForm('/authorize/email', fields);
  const otpHtml = await otp.text();
  const done = await sag.postForm('/authorize/otp', {
    tx: extractField(otpHtml),
    code: extractDevCode(otpHtml),
  });
  return { otp, done };
}

function setCookie(response, name) {
  return (response.headers.getSetCookie?.() ?? []).find((value) => value.startsWith(name + '='));
}

test('the initial email screen offers an unticked remember-me checkbox below the address', async () => {
  const sag = createInstance();
  const { html } = await begin(sag);

  const email = html.indexOf('id="email"');
  const checkbox = html.indexOf('id="remember_me"');
  assert.ok(email >= 0 && checkbox > email, 'the checkbox should follow the email input');
  assert.match(html, /<input id="remember_me" name="remember_me" type="checkbox" value="1"/);
  assert.match(html, /<label for="remember_me">Remember me<\/label>/);
  assert.doesNotMatch(html, /name="remember_me"[^>]*\schecked/);
});

test('a remembered address is stored only after authentication, then prefills and ticks the form', async () => {
  const sag = createInstance();
  const first = await begin(sag);
  const tx = extractField(first.html);

  const otp = await sag.postForm('/authorize/email', { tx, email: EMAIL, remember_me: '1' });
  assert.equal(setCookie(otp, REMEMBER_ME_COOKIE), undefined, 'submitting an address is not authentication');
  const otpHtml = await otp.text();
  const done = await sag.postForm('/authorize/otp', {
    tx: extractField(otpHtml),
    code: extractDevCode(otpHtml),
  });

  const cookie = setCookie(done, REMEMBER_ME_COOKIE);
  assert.ok(cookie, 'successful authentication should set the remember-me cookie');
  assert.match(cookie, new RegExp('Max-Age=' + REMEMBER_ME_TTL_SECONDS + '(?:;|$)'));
  assert.match(cookie, /; Path=\//);
  assert.match(cookie, /; SameSite=Lax/);
  assert.match(cookie, /; HttpOnly/);
  assert.match(cookie, /; Secure/);
  assert.ok(!cookie.includes('Domain='));

  for (const name of [...sag.cookies.keys()]) {
    if (name !== REMEMBER_ME_COOKIE) sag.cookies.delete(name);
  }
  const next = await begin(sag);
  assert.match(next.html, new RegExp('value="' + EMAIL.replace('.', '\\.') + '"'));
  assert.match(next.html, /name="remember_me"[^>]*\schecked/);
  assert.ok(setCookie(next.res, REMEMBER_ME_COOKIE), 'using the remembered address should roll the cookie forward');
});

test('unticking remember me clears an existing cookie after successful authentication', async () => {
  const sag = createInstance();
  const first = await begin(sag);
  await authenticate(sag, { tx: extractField(first.html) });
  assert.ok(sag.cookies.has(REMEMBER_ME_COOKIE));

  const again = await begin(sag, { prompt: 'login' });
  assert.match(again.html, /name="remember_me"[^>]*\schecked/);
  const { done } = await authenticate(sag, { tx: extractField(again.html), remember: false });

  const cleared = setCookie(done, REMEMBER_ME_COOKIE);
  assert.match(cleared, /Max-Age=0/);
  assert.ok(!sag.cookies.has(REMEMBER_ME_COOKIE));
});
