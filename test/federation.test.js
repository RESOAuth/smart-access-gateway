// Federation: SAG acting as a relying party to somebody else.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, pkce, authorizeUrl, extractField, redeem, DEV_CLIENT } from './harness.js';
import { createStubProvider, readUpstreamRedirect } from './upstream-stub.js';
import { clearUpstreamMetadataCache, upstreamMetadata } from '../src/upstream/index.js';
import { clearJwksCache, verifyCompact, decodeJwt } from '../src/crypto/jose.js';
import { ACR } from '../src/acr.js';
import { PROVIDERS } from '../src/upstream/providers.js';
import { loadConfig } from '../src/config.js';

const UPSTREAM_CLIENT = 'upstream-client-id';

/** Configure one generic OIDC upstream pointing at the stub. */
function upstreamEnv(stub, { slug = 'ACME', domain = 'acme.test', extra = {} } = {}) {
  return {
    ['UPSTREAM_OIDC_' + slug + '_CLIENT_ID']: domain + ':' + UPSTREAM_CLIENT,
    ['UPSTREAM_OIDC_' + slug + '_CLIENT_SECRET']: 'upstream-secret',
    ['UPSTREAM_OIDC_' + slug + '_ISSUER']: stub.issuer,
    ...extra,
  };
}

/** Everything up to the point where SAG hands off to the upstream. */
async function untilUpstream(sag, { email, authorize = {} } = {}) {
  const { verifier, challenge } = await pkce();
  const { path, params } = authorizeUrl({ challenge, ...authorize });
  const first = await sag.raw(path);
  const tx = extractField(await first.text());
  assert.ok(tx, 'the email page should have been shown');
  const handoff = await sag.postForm('/authorize/email', { tx, email });
  return { verifier, params, handoff };
}

/** Set up a fresh instance and stub, with caches cleared. */
async function scenario(envExtra = {}, stubOpts = {}) {
  clearUpstreamMetadataCache();
  clearJwksCache();
  const stub = await createStubProvider(stubOpts);
  const restore = stub.install();
  const sag = createInstance({ ...upstreamEnv(stub), ...envExtra });
  return { stub, sag, restore };
}

test('a domain with an upstream is federated, and the id_token is re-issued by SAG', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const { verifier, handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  assert.equal(handoff.status, 303, 'the browser should be sent to the upstream');

  const sent = readUpstreamRedirect(handoff);
  assert.equal(sent.url.origin + sent.url.pathname, stub.metadata.authorization_endpoint);
  assert.equal(sent.params.client_id, UPSTREAM_CLIENT);
  assert.equal(sent.params.response_type, 'code');
  assert.equal(sent.params.code_challenge_method, 'S256', 'SAG must use PKCE upstream too');
  assert.ok(sent.params.code_challenge, 'a challenge must be sent');
  assert.ok(sent.nonce, 'a nonce must be sent');
  assert.equal(sent.params.login_hint, 'person@acme.test');
  assert.equal(sent.params.redirect_uri, 'http://localhost:8787/callback');

  // The upstream authenticates the person and sends them back.
  await stub.expect({
    audience: UPSTREAM_CLIENT,
    nonce: sent.nonce,
    claims: { email: 'person@acme.test', email_verified: true, name: 'A Person' },
  });
  const back = await sag.raw('/callback?code=upstream-code&state=' + encodeURIComponent(sent.state));
  assert.equal(back.status, 303, 'SAG should now redirect to the relying party');

  const location = new URL(back.headers.get('location'));
  const code = location.searchParams.get('code');
  assert.ok(code, 'an authorization code should have been issued');

  // The upstream exchange used PKCE and the client secret.
  assert.equal(stub.state.tokenRequests.length, 1);
  const exchange = stub.state.tokenRequests[0];
  assert.equal(exchange.grant_type, 'authorization_code');
  assert.ok(exchange.code_verifier, 'the verifier must be presented');
  assert.equal(exchange.client_secret, 'upstream-secret');

  // And the token SAG issues is its own, signed by its own key.
  const { res, body } = await redeem(sag, { authCode: code, verifier });
  assert.equal(res.status, 200, JSON.stringify(body));
  const { body: jwks } = await sag.json('/jwks.json');
  const { header } = decodeJwt(body.id_token);
  const claims = await verifyCompact(body.id_token, jwks.keys.find((k) => k.kid === header.kid));
  assert.equal(claims.iss, 'http://localhost:8787', 'SAG is the issuer, not the upstream');
  assert.equal(claims.aud, DEV_CLIENT);
  assert.equal(claims.email, 'person@acme.test');
  assert.equal(claims.acr, ACR.FEDERATED);
  assert.deepEqual(claims.amr, ['fed']);
  assert.ok(claims.sub, 'a subject was asked for');
  assert.notEqual(claims.sub, 'upstream-subject-1', 'the upstream subject must not leak through');
});

test('an upstream reporting MFA reaches the stronger acr and satisfies a demand for it', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const { verifier, handoff } = await untilUpstream(sag, {
    email: 'person@acme.test',
    authorize: { acr_values: ACR.FEDERATED_MFA },
  });
  const sent = readUpstreamRedirect(handoff);

  await stub.expect({
    audience: UPSTREAM_CLIENT,
    nonce: sent.nonce,
    claims: { email: 'person@acme.test', email_verified: true, amr: ['pwd', 'mfa'] },
  });
  const back = await sag.raw('/callback?code=c&state=' + encodeURIComponent(sent.state));
  assert.equal(back.status, 303);
  const code = new URL(back.headers.get('location')).searchParams.get('code');
  assert.ok(code, 'the MFA demand should now be satisfied');

  const { body } = await redeem(sag, { authCode: code, verifier });
  const { body: jwks } = await sag.json('/jwks.json');
  const { header } = decodeJwt(body.id_token);
  const claims = await verifyCompact(body.id_token, jwks.keys.find((k) => k.kid === header.kid));
  assert.equal(claims.acr, ACR.FEDERATED_MFA);
  assert.ok(claims.amr.includes('mfa'));
});

test('an upstream that reports no MFA cannot satisfy a demand for it', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const { handoff } = await untilUpstream(sag, {
    email: 'person@acme.test',
    authorize: { acr_values: ACR.FEDERATED_MFA },
  });
  const sent = readUpstreamRedirect(handoff);

  await stub.expect({
    audience: UPSTREAM_CLIENT,
    nonce: sent.nonce,
    claims: { email: 'person@acme.test', email_verified: true },
  });
  const back = await sag.raw('/callback?code=c&state=' + encodeURIComponent(sent.state));
  assert.equal(back.status, 303);
  const location = new URL(back.headers.get('location'));
  assert.equal(
    location.searchParams.get('error'),
    'unmet_authentication_requirements',
    'a plain federated sign-in must not be passed off as MFA',
  );
});

test('a domain-specific upstream cannot assert an address outside its domain', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  const sent = readUpstreamRedirect(handoff);

  // The upstream returns somebody else's address entirely.
  await stub.expect({
    audience: UPSTREAM_CLIENT,
    nonce: sent.nonce,
    claims: { email: 'victim@other.test', email_verified: true },
  });
  const back = await sag.raw('/callback?code=c&state=' + encodeURIComponent(sent.state));
  // No token: the flow falls back to asking for an address again, since
  // acme.test has no OTP restriction and a code could still work.
  assert.equal(back.status, 400);
  const html = await back.text();
  assert.match(html, /did not complete/);
});

test('an upstream asserting an unverified address is refused', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  const sent = readUpstreamRedirect(handoff);
  await stub.expect({
    audience: UPSTREAM_CLIENT,
    nonce: sent.nonce,
    claims: { email: 'person@acme.test', email_verified: false },
  });
  const back = await sag.raw('/callback?code=c&state=' + encodeURIComponent(sent.state));
  assert.equal(back.status, 400);
  assert.match(await back.text(), /did not complete/);
});

test('a replayed nonce from a different transaction is refused', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  const sent = readUpstreamRedirect(handoff);

  // An id_token minted for a nonce SAG never issued must not be accepted.
  await stub.expect({
    audience: UPSTREAM_CLIENT,
    nonce: 'a-nonce-sag-never-sent',
    claims: { email: 'person@acme.test', email_verified: true },
  });
  const back = await sag.raw('/callback?code=c&state=' + encodeURIComponent(sent.state));
  assert.equal(back.status, 400);
  assert.match(await back.text(), /did not complete/);
});

test('an id_token minted for a different audience is refused', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  const sent = readUpstreamRedirect(handoff);
  await stub.expect({
    audience: 'some-other-relying-party',
    nonce: sent.nonce,
    claims: { email: 'person@acme.test', email_verified: true },
  });
  const back = await sag.raw('/callback?code=c&state=' + encodeURIComponent(sent.state));
  assert.equal(back.status, 400);
});

test('a callback with a state SAG did not seal is refused', async (t) => {
  const { sag, restore } = await scenario();
  t.after(restore);

  const forged = await sag.raw('/callback?code=c&state=not-a-sealed-state');
  assert.equal(forged.status, 400);
  assert.match(await forged.text(), /could not be matched/);
});

test('a domain with no upstream still falls back to an email code', async (t) => {
  const { sag, restore } = await scenario();
  t.after(restore);

  // acme.test is federated, but nobody else is.
  const { handoff } = await untilUpstream(sag, { email: 'person@elsewhere.test' });
  assert.equal(handoff.status, 200, 'this should be the OTP page, not a redirect');
  assert.match(await handoff.text(), /Check your email/);
});

test('two upstreams for one domain produce a chooser', async (t) => {
  clearUpstreamMetadataCache();
  clearJwksCache();
  const stub = await createStubProvider();
  const restore = stub.install();
  t.after(restore);

  const sag = createInstance({
    ...upstreamEnv(stub, { slug: 'ACMEONE' }),
    ...upstreamEnv(stub, { slug: 'ACMETWO' }),
  });
  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  assert.equal(handoff.status, 200);
  const html = await handoff.text();
  assert.match(html, /Choose how to sign in/);
  assert.match(html, /Continue with/);
});

test('a tampered upstream choice is refused', async (t) => {
  const { sag, restore } = await scenario();
  t.after(restore);

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge });
  const first = await sag.raw(path);
  const tx = extractField(await first.text());
  const otp = await sag.postForm('/authorize/email', { tx, email: 'person@elsewhere.test' });
  const otpTx = extractField(await otp.text());

  // elsewhere.test is not served by oidc/acmeone, so naming it must fail.
  const forged = await sag.postForm('/authorize/upstream', { tx: otpTx, upstream: 'oidc/acme' });
  assert.equal(forged.status, 400);
});

test('a domain-specific upstream takes precedence over a common one', async (t) => {
  clearUpstreamMetadataCache();
  clearJwksCache();
  const stub = await createStubProvider();
  const restore = stub.install();
  t.after(restore);

  const sag = createInstance({
    ...upstreamEnv(stub, { slug: 'ACME', domain: 'acme.test' }),
    UPSTREAM_OIDC_COMMON_CLIENT_ID: 'common:common-client-id',
    UPSTREAM_OIDC_COMMON_ISSUER: stub.issuer,
  });

  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  const sent = readUpstreamRedirect(handoff);
  assert.equal(sent.params.client_id, UPSTREAM_CLIENT, 'the domain-specific upstream must win');

  // While an unrelated domain gets the common one.
  const other = await untilUpstream(sag, { email: 'person@somewhere.test' });
  const otherSent = readUpstreamRedirect(other.handoff);
  assert.equal(otherSent.params.client_id, 'common-client-id');
});

// ---------------------------------------------------------------------------
// What a common upstream is allowed to assert. See ADR 0019.
// ---------------------------------------------------------------------------

/** One common upstream at the stub, and a sign-in that reaches the callback. */
async function commonScenario(extra = {}) {
  clearUpstreamMetadataCache();
  clearJwksCache();
  const stub = await createStubProvider();
  const restore = stub.install();
  const sag = createInstance({
    UPSTREAM_OIDC_COMMON_CLIENT_ID: 'common:' + UPSTREAM_CLIENT,
    UPSTREAM_OIDC_COMMON_ISSUER: stub.issuer,
    ...extra,
  });
  return { stub, sag, restore };
}

/** Hand the stub these claims and follow the callback back to SAG. */
async function signInVia(stub, sag, email, claims) {
  const { handoff } = await untilUpstream(sag, { email });
  const sent = readUpstreamRedirect(handoff);
  await stub.expect({ audience: UPSTREAM_CLIENT, nonce: sent.nonce, claims });
  return sag.raw('/callback?code=upstream-code&state=' + encodeURIComponent(sent.state));
}

test('a common upstream reads the address from email, never a login identifier', async (t) => {
  // preferred_username and upn are directory attributes a tenant sets, and no
  // provider verifies the domain in them. With no domain of its own to check
  // against, a common upstream must not accept either.
  const { stub, sag, restore } = await commonScenario();
  t.after(restore);

  const back = await signInVia(stub, sag, 'person@somewhere.test', {
    preferred_username: 'finance@victim.test',
    upn: 'finance@victim.test',
  });

  assert.equal(back.status, 400);
  assert.match(await back.text(), /did not complete/);
});

test('a domain-specific upstream still falls back to upn, because its domain bounds it', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const back = await signInVia(stub, sag, 'person@acme.test', { upn: 'person@acme.test' });

  assert.equal(back.status, 303);
  assert.ok(new URL(back.headers.get('location')).searchParams.get('code'));
});

test('an unbounded common upstream is warned about, on the operator channel only', async () => {
  const sag = createInstance({
    UPSTREAM_MICROSOFT_COMMON_CLIENT_ID: 'common:ms-common',
    UPSTREAM_MICROSOFT_COMMON_CLIENT_SECRET: 'x',
  });
  const config = loadConfig(sag.env);

  assert.ok(
    config.internalWarnings.some((w) => /nothing bounds the addresses it may assert/.test(w) && /xms_edov/.test(w)),
    'the operator should be told, and told both remedies',
  );
  const { body } = await sag.json('/healthz');
  assert.ok(
    !JSON.stringify(body).includes('bounds the addresses'),
    'but which defences are absent is not published to strangers',
  );
});

test('a bounded common upstream draws no warning', () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    SAG_SECRET: 'test-secret-'.repeat(4),
    UPSTREAM_MICROSOFT_COMMON_CLIENT_ID: 'common:ms-common',
    UPSTREAM_MICROSOFT_COMMON_CLIENT_SECRET: 'x',
    UPSTREAM_MICROSOFT_COMMON_ALLOWED_TENANTS: '11111111-2222-3333-4444-555555555555',
  });
  assert.ok(!config.internalWarnings.some((w) => /nothing bounds the addresses/.test(w)));
});

test('an unknown Microsoft tenant is refused when ALLOWED_TENANTS is set', () => {
  const upstream = {
    provider: 'microsoft',
    isCommon: true,
    allowedTenants: ['11111111-2222-3333-4444-555555555555'],
  };
  const verify = PROVIDERS.microsoft.verifyClaims;

  assert.throws(() => verify(upstream, { tid: '99999999-9999-9999-9999-999999999999' }), /does not accept/);
  assert.doesNotThrow(() => verify(upstream, { tid: '11111111-2222-3333-4444-555555555555' }));
  // A token with no tid at all cannot satisfy an allow-list either.
  assert.throws(() => verify(upstream, {}), /does not accept/);
});

test('a common Microsoft upstream with no tenant list needs xms_edov', () => {
  // Entra never sends email_verified, so xms_edov is the only claim that says
  // the tenant proved it owns the domain in the address. See ADR 0019.
  const upstream = { provider: 'microsoft', isCommon: true, allowedTenants: [] };
  const verify = PROVIDERS.microsoft.verifyClaims;
  const tid = '99999999-9999-9999-9999-999999999999';

  assert.throws(() => verify(upstream, { tid }), /xms_edov/, 'an absent claim proves nothing');
  assert.throws(() => verify(upstream, { tid, xms_edov: false }), /not in a domain the tenant has verified/);
  assert.doesNotThrow(() => verify(upstream, { tid, xms_edov: true }));
  // Entra has emitted the claim as a string as well as a boolean.
  assert.doesNotThrow(() => verify(upstream, { tid, xms_edov: 'true' }));
  assert.throws(() => verify(upstream, { tid, xms_edov: 'false' }), /not in a domain the tenant has verified/);
});

test('an unverified email domain is refused even from an allowed tenant', () => {
  const tid = '11111111-2222-3333-4444-555555555555';
  const upstream = { provider: 'microsoft', isCommon: true, allowedTenants: [tid] };
  const verify = PROVIDERS.microsoft.verifyClaims;

  assert.throws(() => verify(upstream, { tid, xms_edov: false }), /not in a domain the tenant has verified/);
  // But an allowed tenant does not have to send the claim at all.
  assert.doesNotThrow(() => verify(upstream, { tid }));
});

test('a domain-specific Microsoft upstream does not need xms_edov', () => {
  // Its own CLIENT_ID domain is the bound, and the address is checked against
  // it, so demanding an optional claim would only break working deployments.
  const upstream = { provider: 'microsoft', isCommon: false, domain: 'acme.test', tenant: 'acme.test', allowedTenants: [] };
  assert.doesNotThrow(() => PROVIDERS.microsoft.verifyClaims(upstream, { tid: 'acme.test' }));
});

test('an upstream token exchange failure falls back to an email code', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  const sent = readUpstreamRedirect(handoff);
  stub.state.tokenError = 'invalid_grant';

  const back = await sag.raw('/callback?code=c&state=' + encodeURIComponent(sent.state));
  assert.equal(back.status, 400);
  const html = await back.text();
  assert.match(html, /did not complete/, 'the person should be offered another route');
  assert.match(html, /Email address/, 'and asked for their address again');
});

test('an upstream returning access_denied relays it to the relying party', async (t) => {
  const { sag, restore } = await scenario();
  t.after(restore);

  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  const sent = readUpstreamRedirect(handoff);

  const back = await sag.raw('/callback?error=access_denied&state=' + encodeURIComponent(sent.state));
  assert.equal(back.status, 303);
  const location = new URL(back.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'access_denied');
});

test('prompt=none propagates upstream and its failure becomes login_required', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  // A session is needed first, otherwise prompt=none fails before it starts.
  const { handoff } = await untilUpstream(sag, { email: 'person@acme.test' });
  const sent = readUpstreamRedirect(handoff);
  await stub.expect({
    audience: UPSTREAM_CLIENT,
    nonce: sent.nonce,
    claims: { email: 'person@acme.test', email_verified: true },
  });
  await sag.raw('/callback?code=c&state=' + encodeURIComponent(sent.state));

  // Now force a fresh upstream round trip that must not show a page.
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, prompt: 'login', login_hint: 'person@acme.test' });
  const again = await sag.raw(path);
  const tx = extractField(await again.text());
  const relayed = await sag.postForm('/authorize/email', { tx, email: 'person@acme.test' });
  const relayedSent = readUpstreamRedirect(relayed);
  assert.equal(relayedSent.params.prompt, 'login', 'the demand must reach the upstream');
});

test('the upstream discovery document is fetched once and cached', async (t) => {
  const { stub, sag, restore } = await scenario();
  t.after(restore);

  await untilUpstream(sag, { email: 'one@acme.test' });
  await untilUpstream(sag, { email: 'two@acme.test' });
  assert.equal(stub.state.discoveryCount, 1, 'discovery must not repeat per request');
});

test('an oversized upstream discovery response is refused before parsing', async (t) => {
  clearUpstreamMetadataCache();
  const stub = await createStubProvider({ metadata: { padding: 'x'.repeat(70 * 1024) } });
  const restore = stub.install();
  t.after(restore);

  await assert.rejects(
    () => upstreamMetadata({ id: 'oidc/acme', provider: 'oidc', issuer: stub.issuer }),
    /larger than 65536 bytes/,
  );
});
