// The end-to-end flow, driven exactly as a browser and a relying party would.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, redeem, pkce, authorizeUrl, extractField, DEV_CLIENT, DEV_REDIRECT } from './harness.js';
import { verifyCompact, decodeJwt, validateClaims } from '../src/crypto/jose.js';
import { ACR } from '../src/acr.js';

const EMAIL = 'someone@example.org';

test('a full email-code sign-in produces a verifiable id_token', async () => {
  const sag = createInstance();

  const flow = await signInWithOtp(sag, { email: EMAIL });
  assert.equal(flow.returnedState, flow.state, 'state must be returned unchanged');
  assert.equal(flow.iss, 'http://localhost:8787', 'RFC 9207 iss must be present');

  const { res, body } = await redeem(sag, flow);
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.equal(body.token_type, 'Bearer');
  assert.ok(body.id_token, 'an id_token must be issued');
  assert.ok(body.access_token, 'an access token must be issued for /userinfo');
  assert.equal(body.scope, 'openid email');

  // Verify the id_token the way a relying party would: fetch the JWKS, pick
  // the key by kid, check the signature, then check every claim.
  const { body: jwks } = await sag.json('/jwks.json');
  const { header } = decodeJwt(body.id_token);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  assert.ok(jwk, 'the kid in the id_token header must be published in the JWKS');

  const claims = await verifyCompact(body.id_token, jwk, { algs: ['ES256'] });
  validateClaims(claims, { issuer: 'http://localhost:8787', audience: DEV_CLIENT, nonce: flow.nonce });
  assert.equal(claims.email, EMAIL);
  assert.equal(claims.email_verified, true);
  assert.equal(claims.acr, ACR.OTP, 'an email code is the weakest context');
  assert.deepEqual(claims.amr, ['otp', 'email']);
  assert.ok(claims.sub && claims.sub !== EMAIL, 'the subject must not be the address itself');
  assert.ok(claims.sid, 'a session identifier is needed for logout');
  assert.ok(claims.at_hash, 'at_hash is required when an access token is issued');

  // The access token works at /userinfo and reports the same person.
  const { res: uiRes, body: userinfo } = await sag.json('/userinfo', {
    headers: { authorization: 'Bearer ' + body.access_token },
  });
  assert.equal(uiRes.status, 200);
  assert.equal(userinfo.sub, claims.sub);
  assert.equal(userinfo.email, EMAIL);
});

test('a code presented with the wrong PKCE verifier is refused', async () => {
  const sag = createInstance();
  const flow = await signInWithOtp(sag, { email: EMAIL });

  // Wrong verifier is refused.
  const { verifier: otherVerifier } = await pkce();
  const wrong = await redeem(sag, { ...flow, verifier: otherVerifier });
  assert.equal(wrong.res.status, 400);
  assert.equal(wrong.body.error, 'invalid_grant');

  // The right one still works, because a failed attempt is not a redemption.
  const ok = await redeem(sag, flow);
  assert.equal(ok.res.status, 200, JSON.stringify(ok.body));
});

test('a code is bound to the client and the redirect URI it was issued for', async () => {
  // Declaring any client at all suppresses the development default, so both
  // have to be named here.
  const sag = createInstance({
    CLIENT_DEV_ID: DEV_CLIENT,
    CLIENT_DEV_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_OTHER_ID: 'other-client',
    CLIENT_OTHER_REDIRECT_URIS: DEV_REDIRECT + ' http://localhost:8788/callback',
  });
  const flow = await signInWithOtp(sag, { email: EMAIL });

  const wrongClient = await redeem(sag, { ...flow, clientId: 'other-client' });
  assert.equal(wrongClient.body.error, 'invalid_grant');

  const missingRedirect = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      client_id: DEV_CLIENT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal((await missingRedirect.json()).error, 'invalid_grant', 'redirect_uri must be repeated at /token');

  const wrongRedirect = await redeem(sag, { ...flow, redirectUri: 'http://localhost:8788/callback' });
  assert.equal(wrongRedirect.body.error, 'invalid_grant');
});

test('an omitted prompt asks to confirm the existing session, while prompt=none is silent', async () => {
  const sag = createInstance();
  await signInWithOtp(sag, { email: EMAIL });

  // A fresh authorisation request defaults to consent, so account use is
  // visible unless the relying party explicitly opts into transparency.
  const { verifier, challenge } = await pkce();
  const { path } = authorizeUrl({ challenge });
  const res = await sag.raw(path);
  assert.equal(res.status, 200, 'an omitted prompt should show the account confirmation');
  const html = await res.text();
  assert.match(html, /Continue as/);
  assert.match(html, new RegExp(EMAIL));

  const blank = authorizeUrl({ challenge, prompt: '' });
  const blankRes = await sag.raw(blank.path);
  assert.equal(blankRes.status, 200, 'a blank prompt must not opt into a transparent response');

  // prompt=none remains the explicit request for a transparent response.
  const silent = authorizeUrl({ challenge, prompt: 'none' });
  const silentRes = await sag.raw(silent.path);
  assert.equal(silentRes.status, 303);
  const silentLocation = new URL(silentRes.headers.get('location'));
  assert.ok(silentLocation.searchParams.get('code'), 'prompt=none must be answerable');

  const { res: tokenRes, body } = await redeem(sag, {
    authCode: silentLocation.searchParams.get('code'),
    verifier,
  });
  assert.equal(tokenRes.status, 200, JSON.stringify(body));
});

test('prompt=none without a session returns login_required to the relying party', async () => {
  const sag = createInstance();
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'none' });
  const res = await sag.raw(path);
  assert.equal(res.status, 303);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'login_required');
  assert.equal(location.origin + location.pathname, DEV_REDIRECT);
});

test('prompt=login forces re-authentication even with a session', async () => {
  const sag = createInstance();
  await signInWithOtp(sag, { email: EMAIL });

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'login' });
  const res = await sag.raw(path);
  assert.equal(res.status, 200, 'prompt=login must show the sign-in page');
  const body = await res.text();
  assert.match(body, /Email address/);
});

test('prompt=consent asks the person to confirm the account', async () => {
  const sag = createInstance();
  await signInWithOtp(sag, { email: EMAIL });

  const { verifier, challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'consent' });
  const res = await sag.raw(path);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Continue as/);
  assert.match(html, new RegExp(EMAIL));

  const tx = extractField(html);
  const done = await sag.postForm('/authorize/continue', { tx });
  assert.equal(done.status, 303);
  const code = new URL(done.headers.get('location')).searchParams.get('code');
  const { res: tokenRes } = await redeem(sag, { authCode: code, verifier });
  assert.equal(tokenRes.status, 200);
});

test('an acr demand that email codes cannot satisfy is refused rather than downgraded', async () => {
  const sag = createInstance();
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, acr_values: ACR.FEDERATED_MFA });

  const res = await sag.raw(path);
  assert.equal(res.status, 200, 'the address is still asked for');

  const tx = extractField(await res.text());
  const next = await sag.postForm('/authorize/email', { tx, email: EMAIL });
  // No upstream covers example.org, and an email code is too weak, so the
  // request must fail back to the relying party rather than issue a token.
  assert.equal(next.status, 303);
  const location = new URL(next.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'unmet_authentication_requirements');
});

test('an existing weak session does not satisfy a stronger acr demand', async () => {
  const sag = createInstance();
  await signInWithOtp(sag, { email: EMAIL });

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, acr_values: ACR.FEDERATED_MFA, prompt: 'none' });
  const res = await sag.raw(path);
  assert.equal(res.status, 303);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'unmet_authentication_requirements');
});

test('form_post response mode posts the code instead of putting it in a URL', async () => {
  const sag = createInstance();
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, response_mode: 'form_post' });

  const res = await sag.raw(path);
  const tx = extractField(await res.text());
  const otp = await sag.postForm('/authorize/email', { tx, email: EMAIL });
  const otpHtml = await otp.text();
  const code = otpHtml.match(/<code>([0-9A-Z]+)<\/code>/)[1];
  const done = await sag.postForm('/authorize/otp', { tx: extractField(otpHtml), code });

  assert.equal(done.status, 200);
  const html = await done.text();
  assert.match(html, /<form method="post" action="http:\/\/127\.0\.0\.1:8788\/callback" data-autosubmit>/);
  assert.match(html, /name="code"/);
  assert.match(html, /<noscript>/, 'it must still work without script');
  // The page's only job is to post to the relying party, and its own policy
  // says so: nothing else on it may go anywhere.
  assert.equal(
    done.headers.get('content-security-policy'),
    "default-src 'none'; base-uri 'none'; script-src 'self'; form-action http://127.0.0.1:8788; frame-ancestors 'none'",
  );
});

test('an unknown client is refused without redirecting anywhere', async () => {
  const sag = createInstance();
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, clientId: 'not-registered' });
  const res = await sag.raw(path);
  assert.equal(res.status, 401);
  assert.equal(res.headers.get('location'), null, 'an unknown client must never be redirected');
});

test('an unregistered redirect URI is refused without redirecting to it', async () => {
  const sag = createInstance();
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, redirect_uri: 'https://attacker.example/callback' });
  const res = await sag.raw(path);
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('location'), null, 'this is how an open redirector happens');
  assert.match(await res.text(), /not valid|not registered/i);
});

test('PKCE is mandatory', async () => {
  const sag = createInstance();
  const { path } = authorizeUrl({ challenge: undefined, code_challenge: undefined, code_challenge_method: undefined });
  const res = await sag.raw(path);
  assert.equal(res.status, 303);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'invalid_request');
  assert.match(location.searchParams.get('error_description'), /PKCE/);
});

test('a wrong code is rejected and the attempt is counted', async () => {
  const sag = createInstance();
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge });
  const res = await sag.raw(path);
  const tx = extractField(await res.text());
  const otp = await sag.postForm('/authorize/email', { tx, email: EMAIL });
  const otpHtml = await otp.text();

  const bad = await sag.postForm('/authorize/otp', { tx: extractField(otpHtml), code: '000000' });
  assert.equal(bad.status, 400);
  const badHtml = await bad.text();
  assert.match(badHtml, /not right/);
  assert.match(badHtml, /attempts left/);
});

test('signing out clears the session so the next request needs interaction', async () => {
  const sag = createInstance();
  await signInWithOtp(sag, { email: EMAIL });

  const out = await sag.raw('/logout');
  assert.equal(out.status, 200);
  const html = await out.text();
  // A shared session affects every relying party, so it must be confirmed.
  assert.match(html, /Sign out\?/);
  const token = extractField(html, 'lt');
  const done = await sag.postForm('/logout', { lt: token });
  assert.equal(done.status, 200);
  assert.match(await done.text(), /You are signed out/);

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'none' });
  const after = await sag.raw(path);
  const location = new URL(after.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'login_required');
});

test('with no replay store configured a code is redeemable more than once', async () => {
  // This is the default, and it is a trade-off rather than a desired property:
  // with no store there is nothing to mark a code as spent. PKCE, a 60 second
  // lifetime and client binding keep the window small. Setting
  // STATE_STORE_BACKEND closes it entirely - see test/state-store.test.js -
  // and docs/state-and-limits.md carries the recommendation per platform.
  const sag = createInstance();
  const flow = await signInWithOtp(sag, { email: EMAIL });

  const first = await redeem(sag, flow);
  assert.equal(first.res.status, 200);
  const second = await redeem(sag, flow);
  assert.equal(second.res.status, 200, 'known limitation, not a desired property');
});
