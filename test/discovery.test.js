// Discovery.
//
// The claim under test is that these documents describe *this* instance. A
// relying party reads them once at start-up and then trusts them for the life
// of the deployment, so an algorithm, a claim or an authentication context
// listed here and not actually reachable is a failure that surfaces mid
// sign-in, which is the worst possible moment.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, DEV_CLIENT, DEV_REDIRECT } from './harness.js';
import { supportsAlg } from '../src/crypto/capabilities.js';

const UPSTREAM = {
  UPSTREAM_MICROSOFT_COMMON_CLIENT_ID: 'common:ms-id',
  UPSTREAM_MICROSOFT_COMMON_CLIENT_SECRET: 'ms-secret',
};

const openid = (sag) => sag.json('/.well-known/openid-configuration');
const oauth = (sag) => sag.json('/.well-known/oauth-authorization-server');

// ---------------------------------------------------------------------------
// Where the documents are
// ---------------------------------------------------------------------------

test('all three metadata documents are served, and describe one deployment', async () => {
  const sag = createInstance();
  const { res, body: oidc } = await openid(sag);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /application\/json/);
  assert.match(res.headers.get('cache-control'), /public, max-age=\d+/);

  const { body: as } = await oauth(sag);
  const { body: resource } = await sag.json('/.well-known/oauth-protected-resource');

  assert.equal(oidc.issuer, 'http://localhost:8787');
  assert.equal(as.issuer, oidc.issuer);
  assert.equal(resource.authorization_servers[0], oidc.issuer);
  assert.equal(resource.resource, oidc.userinfo_endpoint);
  // Everything shared between the two authorization documents must agree, or a
  // relying party gets a different deployment depending on which it read.
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'id_token_signing_alg_values_supported']) {
    assert.deepEqual(as[key], oidc[key], key + ' differs between the two documents');
  }
});

test('the OAuth document leaves out what only an OpenID Connect client can use', async () => {
  const sag = createInstance();
  const { body: as } = await oauth(sag);
  for (const key of ['claims_supported', 'prompt_values_supported', 'end_session_endpoint', 'subject_types_supported']) {
    assert.equal(as[key], undefined, 'RFC 8414 metadata should not carry ' + key);
  }
  // RFC 9126: said out loud so a client does not probe for an endpoint that is
  // not there.
  assert.equal(as.require_pushed_authorization_requests, false);
});

test('the JWKS is at the well-known path, and the old one still answers', async () => {
  const sag = createInstance();
  const { body: oidc } = await openid(sag);
  assert.equal(oidc.jwks_uri, 'http://localhost:8787/.well-known/jwks.json');

  const wellKnown = await sag.json('/.well-known/jwks.json');
  const legacy = await sag.json('/jwks.json');
  assert.equal(wellKnown.res.status, 200);
  assert.deepEqual(legacy.body, wellKnown.body, 'both paths must publish the same keys');
  assert.ok(wellKnown.body.keys.length > 0);
  for (const key of wellKnown.body.keys) assert.equal(key.d, undefined, 'no private component may be published');
});

test('RFC 8414 puts the well-known path before a base path, and that is honoured', async () => {
  // OpenID Connect appends: <issuer>/.well-known/openid-configuration.
  // RFC 8414 inserts: <host>/.well-known/oauth-authorization-server<path>.
  // A deployment behind a path prefix has to answer at both.
  const sag = createInstance({ SAG_ISSUER: 'http://localhost:8787/prod' });
  // Absolute, because the harness resolves a bare path against the issuer -
  // which already carries the base path these URLs are about.
  const at = (p) => 'http://localhost:8787' + p;

  const oidc = await sag.json(at('/prod/.well-known/openid-configuration'));
  assert.equal(oidc.res.status, 200);
  assert.equal(oidc.body.issuer, 'http://localhost:8787/prod');

  const as = await sag.json(at('/.well-known/oauth-authorization-server/prod'));
  assert.equal(as.res.status, 200);
  assert.equal(as.body.issuer, 'http://localhost:8787/prod');

  const resource = await sag.json(at('/.well-known/oauth-protected-resource/prod'));
  assert.equal(resource.res.status, 200);
  assert.equal(resource.body.resource, 'http://localhost:8787/prod/userinfo');

  // Somebody else's base path is not ours.
  assert.equal((await sag.raw(at('/.well-known/oauth-authorization-server/staging'))).status, 404);
});

// ---------------------------------------------------------------------------
// Only what this instance can do
// ---------------------------------------------------------------------------

test('an instance with no upstream provider does not advertise federation', async () => {
  const { body } = await openid(createInstance());
  assert.deepEqual(body.acr_values_supported, ['urn:sag:acr:email-otp']);

  const { body: federated } = await openid(createInstance(UPSTREAM));
  assert.deepEqual(federated.acr_values_supported, [
    'urn:sag:acr:email-otp',
    'urn:sag:acr:federated',
    'urn:sag:acr:federated-mfa',
  ]);
});

test('an instance with email codes switched off advertises only federation', async () => {
  const { body } = await openid(createInstance({ ...UPSTREAM, OTP_ENABLED: 'false' }));
  assert.deepEqual(body.acr_values_supported, ['urn:sag:acr:federated', 'urn:sag:acr:federated-mfa']);
});

test('profile is not offered when nothing could ever fill it', async () => {
  // No upstream, and no inference: there is no source for a name or a picture,
  // so asking for the scope would return nothing and listing it would lie.
  const { body: bare } = await openid(createInstance());
  assert.deepEqual(bare.scopes_supported, ['openid', 'email']);
  for (const claim of ['name', 'picture', 'given_name']) {
    assert.ok(!bare.claims_supported.includes(claim), claim + ' must not be listed');
  }

  const { body: federated } = await openid(createInstance(UPSTREAM));
  assert.ok(federated.scopes_supported.includes('profile'));
  assert.ok(federated.claims_supported.includes('name'));
  assert.ok(federated.claims_supported.includes('picture'));
});

test('a narrowed profile claim list narrows the document with it', async () => {
  const { body } = await openid(createInstance({ ...UPSTREAM, PROFILE_CLAIMS: 'name', PROFILE_PICTURE: 'false' }));
  assert.ok(body.claims_supported.includes('name'));
  assert.ok(!body.claims_supported.includes('picture'));
  assert.ok(!body.claims_supported.includes('given_name'));
});

test('guessing a name from an address adds the claim, and says it is a guess', async () => {
  const { body } = await openid(createInstance({ PROFILE_NAME_FROM_EMAIL: 'infer' }));
  assert.ok(body.scopes_supported.includes('profile'));
  assert.ok(body.claims_supported.includes('name'));
  assert.ok(
    body.claims_supported.includes('urn:sag:name_inferred'),
    'a relying party has to be able to tell a guess from an assertion',
  );
  // Nothing else becomes reachable just because a name was guessed.
  assert.ok(!body.claims_supported.includes('given_name'));
  assert.ok(!body.claims_supported.includes('picture'));
});

test('the initials avatar makes picture reachable without an upstream', async () => {
  const { body } = await openid(
    createInstance({ PROFILE_NAME_FROM_EMAIL: 'infer', PROFILE_AVATAR_FALLBACK: 'initials' }),
  );
  assert.ok(body.claims_supported.includes('picture'));
});

test('only the signing algorithms this instance holds keys for are offered', async () => {
  const { body: classical } = await openid(createInstance());
  assert.deepEqual(classical.id_token_signing_alg_values_supported, ['ES256']);
  assert.equal(classical['urn:sag:post_quantum_signing_supported'], false);
  assert.deepEqual(classical['urn:sag:post_quantum_algs'], []);

  const { body: pq } = await openid(createInstance({ SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44' }));
  const hasPq = await supportsAlg('ML-DSA-44');
  assert.deepEqual(pq.id_token_signing_alg_values_supported, hasPq ? ['ES256', 'ML-DSA-44'] : ['ES256']);
  assert.equal(pq['urn:sag:post_quantum_signing_supported'], hasPq);
  assert.deepEqual(pq['urn:sag:post_quantum_algs'], hasPq ? ['ML-DSA-44'] : []);
});

test('consent is only listed when the confirm screen actually appears', async () => {
  const { body: on } = await openid(createInstance());
  assert.ok(on.prompt_values_supported.includes('consent'));

  const { body: off } = await openid(createInstance({ PROMPT_CONSENT_MODE: 'off' }));
  assert.ok(!off.prompt_values_supported.includes('consent'));
  assert.ok(off.prompt_values_supported.includes('none'), 'the others are unaffected');
});

test('token endpoint auth methods are the ones this deployment can accept', async () => {
  // Clients can only come from the environment here, and the one that is there
  // is confidential, so offering `none` would invite a public client that
  // would be refused at /token.
  const fixed = createInstance({
    CLIENTS_CIMD_ENABLED: 'false',
    CLIENT_APP_ID: 'ledger',
    CLIENT_APP_SECRET: 'shhh',
    CLIENT_APP_AUTH_METHOD: 'client_secret_basic',
    CLIENT_APP_REDIRECT_URIS: 'https://ledger.test/cb',
  });
  const { body } = await openid(fixed);
  assert.deepEqual(body.token_endpoint_auth_methods_supported, ['client_secret_basic']);
  assert.equal(body.token_endpoint_auth_signing_alg_values_supported, undefined);

  // Switch on any source that can introduce a client we have not seen and
  // every method the code supports is possible again.
  const { body: dynamic } = await openid(createInstance({ CLIENTS_CIMD_ENABLED: 'true' }));
  assert.deepEqual(dynamic.token_endpoint_auth_methods_supported, [
    'none',
    'client_secret_basic',
    'client_secret_post',
    'private_key_jwt',
  ]);
  assert.ok(dynamic.token_endpoint_auth_signing_alg_values_supported.includes('ES256'));
});

test('pairwise subjects are advertised only where they are configurable', async () => {
  const { body: pub } = await openid(createInstance({ CLIENTS_CIMD_ENABLED: 'false' }));
  assert.deepEqual(pub.subject_types_supported, ['public']);

  const { body: pairwise } = await openid(
    createInstance({ CLIENTS_CIMD_ENABLED: 'false', SUBJECT_TYPE: 'pairwise', SUBJECT_SALT: 'x'.repeat(32) }),
  );
  assert.deepEqual(pairwise.subject_types_supported, ['pairwise']);

  // A client record can name a type this instance has not been told about, so
  // both stay possible answers while either source is switched on.
  const { body: viaStore } = await openid(createInstance());
  assert.deepEqual(viaStore.subject_types_supported.sort(), ['pairwise', 'public']);
});

test('the operator legal links become the standard metadata for them', async () => {
  const { body } = await openid(
    createInstance({ UI_TERMS_URL: 'https://acme.test/terms', UI_PRIVACY_URL: 'https://acme.test/privacy' }),
  );
  assert.equal(body.op_tos_uri, 'https://acme.test/terms');
  assert.equal(body.op_policy_uri, 'https://acme.test/privacy');
});

// ---------------------------------------------------------------------------
// The protected resource
// ---------------------------------------------------------------------------

test('userinfo points a client at its own metadata when it refuses one', async () => {
  const sag = createInstance();
  const res = await sag.raw('/userinfo');
  assert.equal(res.status, 401);
  const challenge = res.headers.get('www-authenticate');
  assert.match(challenge, /^Bearer realm="userinfo"/);
  // RFC 9728: this is the discovery path, so it has to be the real document.
  const match = /resource_metadata="([^"]+)"/.exec(challenge);
  assert.ok(match, 'the challenge must name the resource metadata');
  const { res: metaRes, body } = await sag.json(new URL(match[1]).pathname);
  assert.equal(metaRes.status, 200);
  assert.deepEqual(body.bearer_methods_supported, ['header', 'body']);
});

test('what discovery claims about PKCE is what the endpoint enforces', async () => {
  const sag = createInstance();
  const { body } = await openid(sag);
  assert.deepEqual(body.code_challenge_methods_supported, ['S256']);
  assert.equal(body['urn:sag:require_pkce'], true);

  // So a request without a challenge must be refused rather than accepted.
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: DEV_CLIENT,
    redirect_uri: DEV_REDIRECT,
    scope: 'openid',
    state: 'abc',
  });
  const res = await sag.raw('/authorize?' + params);
  assert.equal(res.status, 303, 'the error goes back to the relying party');
  assert.match(res.headers.get('location'), /error=invalid_request/);
});
