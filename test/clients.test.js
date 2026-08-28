// Relying party identification, authentication and session scoping.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, redeem, pkce, authorizeUrl, DEV_CLIENT, DEV_REDIRECT } from './harness.js';
import { resolveClient, redirectUriAllowed, clearCimdCache } from '../src/clients/index.js';
import { createClientStore } from '../src/clients/store.js';
import { subjectFor, sectorFor } from '../src/identity.js';
import { loadConfig } from '../src/config.js';
import {
  signCompact,
  publicPartOf,
  jwkThumbprint,
  verifyCompact,
  decodeJwt,
  selectJwk,
  fetchJwks,
  clearJwksCache,
} from '../src/crypto/jose.js';
import { sha256hex } from '../src/crypto/secrets.js';
import { nowSeconds, randomToken } from '../src/util/bytes.js';
import { parseAuthorizationRequest } from '../src/oauth/request.js';
import { ACR } from '../src/acr.js';

const EMAIL = 'person@example.org';
const APP = 'https://app.example.test';

// ---------------------------------------------------------------------------
// Redirect URI matching
// ---------------------------------------------------------------------------

test('a client authentication method that is not one of the four is refused', async () => {
  // It used to be invisible: the client was configured with a method nothing
  // checks, and discovery then described the deployment from a set containing
  // it. One misconfigured client is not an outage for everybody else, so it is
  // dropped and reported rather than refused a start - the same way every other
  // client misconfiguration here is.
  const env = {
    CLIENT_APP_ID: 'ledger',
    CLIENT_APP_SECRET: 'shhh',
    CLIENT_APP_AUTH_METHOD: 'client_secret_jwt',
    CLIENT_APP_REDIRECT_URIS: 'https://ledger.test/cb',
    CLIENTS_CIMD_ENABLED: 'false',
  };
  const sag = createInstance(env);

  // To the operator, not to /healthz: the message names a relying party.
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787', ...env });
  assert.ok(
    config.internalWarnings.some((w) => w.includes('AUTH_METHOD="client_secret_jwt"') && w.includes('APP')),
    'the operator has to be told which client and which value: ' + JSON.stringify(config.internalWarnings),
  );

  // Dropped, not half-configured: a client whose authentication nothing
  // implements must not be usable at all.
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, clientId: 'ledger', redirectUri: 'https://ledger.test/cb' });
  const res = await sag.raw(path);
  // 401, the same as any unknown client: the point is that it is refused
  // without a redirect, which is what stops /authorize being an open redirector.
  assert.equal(res.status, 401, 'and it must not be able to start a sign-in');
  assert.equal(res.headers.get('location'), null, 'and refused without redirecting anywhere');
  assert.match(await res.text(), /not recognised/);

  // And discovery does not describe the deployment from a method it refused.
  const { body: meta } = await sag.json('/.well-known/openid-configuration');
  assert.ok(!meta.token_endpoint_auth_methods_supported.includes('client_secret_jwt'));
});

test('an invalid per-client session scope is refused rather than becoming shared', () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENT_APP_ID: 'ledger',
    CLIENT_APP_REDIRECT_URIS: 'https://ledger.test/cb',
    CLIENT_APP_SESSION_SCOPE: 'private',
  });
  assert.equal(
    config.clients.static.find((client) => client.clientId === 'ledger'),
    undefined,
    'a typo must not silently weaken isolation',
  );
  assert.ok(config.internalWarnings.some((w) => /SESSION_SCOPE must be shared or rp/.test(w)));
});

test('redirect URIs match exactly, with the loopback port exception', () => {
  const client = {
    redirectUris: ['https://app.example.test/callback', 'http://127.0.0.1:1234/cb'],
  };
  assert.ok(redirectUriAllowed(client, 'https://app.example.test/callback'));

  // Every one of these has been used to smuggle a code somewhere else.
  assert.ok(!redirectUriAllowed(client, 'https://app.example.test/callback/'), 'a trailing slash is a different URI');
  assert.ok(!redirectUriAllowed(client, 'https://app.example.test/callback?x=1'), 'an added query is not a match');
  assert.ok(!redirectUriAllowed(client, 'https://app.example.test.evil/callback'));
  assert.ok(!redirectUriAllowed(client, 'https://app.example.test/callback/../../evil'));
  assert.ok(!redirectUriAllowed(client, 'http://app.example.test/callback'), 'the scheme must match');
  assert.ok(!redirectUriAllowed(client, 'https://evil.test/callback'));
  assert.ok(!redirectUriAllowed(client, 'not a url'));

  // RFC 8252: a native application cannot know which loopback port it gets.
  assert.ok(redirectUriAllowed(client, 'http://127.0.0.1:59123/cb'), 'the loopback port is ignored');
  assert.ok(!redirectUriAllowed(client, 'http://127.0.0.1:59123/other'), 'but the path is not');
  assert.ok(!redirectUriAllowed(client, 'http://localhost:59123/cb'), 'and nor is the host');

  const native = { redirectUris: ['example-app:/oauth/callback'] };
  assert.ok(redirectUriAllowed(native, 'example-app:/oauth/callback'), 'custom schemes are permitted by default');
  assert.ok(
    !redirectUriAllowed(native, 'example-app:/oauth/callback', ['https', 'http']),
    'an explicit scheme allow list narrows the permissive default',
  );
});

test('redirect URI scheme configuration is normalised and validated', () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_REDIRECT_URI_SCHEMES: 'HTTPS, example-app:',
  });
  assert.deepEqual(config.clients.redirectUriSchemes, ['https', 'example-app']);
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', CLIENTS_REDIRECT_URI_SCHEMES: 'not/a/scheme' }),
    /contains an invalid URI scheme/,
  );
});

test('an authorisation request enforces the configured redirect scheme allow-list', async () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_REDIRECT_URI_SCHEMES: 'https,http',
  });
  const client = { clientId: 'native', redirectUris: ['example-app:/callback'], requirePkce: true };
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: client.redirectUris[0],
    scope: 'openid',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
  });
  await assert.rejects(
    () => parseAuthorizationRequest(params, config, { resolveClient: async () => client }),
    (error) => error.code === 'invalid_request' && error.redirectable === false && /allowed scheme/.test(error.description),
  );
});

test('one client ACR floor cannot mutate the instance default for later clients', async () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    ACR_DEFAULT_REQUIRED: ACR.OTP,
  });
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'one',
    redirect_uri: 'https://one.test/cb',
    scope: 'openid',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
  });
  const client = {
    clientId: 'one',
    redirectUris: ['https://one.test/cb'],
    requirePkce: true,
    acrValues: [ACR.FEDERATED_MFA],
  };

  const parsed = await parseAuthorizationRequest(params, config, { resolveClient: async () => client });
  assert.deepEqual(parsed.request.acrValues, [ACR.OTP, ACR.FEDERATED_MFA]);
  assert.deepEqual(config.acr.defaultRequired, [ACR.OTP], 'the shared configuration must stay unchanged');
});

test('an authorisation request cannot override the client signing algorithm', async () => {
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'one',
    redirect_uri: 'https://one.test/cb',
    scope: 'openid',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
    id_token_signed_response_alg: 'ES256',
  });
  const client = {
    clientId: 'one',
    redirectUris: ['https://one.test/cb'],
    requirePkce: true,
    idTokenSignedResponseAlg: 'ML-DSA-44',
  };

  await assert.rejects(
    () => parseAuthorizationRequest(params, config, { resolveClient: async () => client }),
    (err) => err.code === 'invalid_request' && /does not match this client registration/.test(err.description),
  );
});

// ---------------------------------------------------------------------------
// Client authentication at /token
// ---------------------------------------------------------------------------

test('a confidential client must present its secret, and a wrong one is refused', async () => {
  const sag = createInstance({
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_APP_SECRET: 'The-Real-Secret',
    CLIENT_APP_AUTH_METHOD: 'client_secret_basic',
  });

  const flow = await signInWithOtp(sag, { email: EMAIL });
  const basic = (secret) => 'Basic ' + Buffer.from(DEV_CLIENT + ':' + secret).toString('base64');

  const none = await redeem(sag, flow);
  assert.equal(none.res.status, 401, 'no credential must be refused');
  assert.equal(none.body.error, 'invalid_client');

  const wrong = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic('wrong') },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(wrong.status, 401);

  const wrongCase = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic('the-real-secret') },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(wrongCase.status, 401, 'plain client secrets are case-sensitive');

  const wrongMethod = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      code_verifier: flow.verifier,
      client_id: DEV_CLIENT,
      client_secret: 'The-Real-Secret',
    }).toString(),
  });
  assert.equal(wrongMethod.status, 401, 'a basic client must not be accepted through client_secret_post');

  const right = await sag.raw('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic('The-Real-Secret') },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(right.status, 200, JSON.stringify(await right.clone().json()));
});

test('a public client presenting a secret is refused', async () => {
  const sag = createInstance();
  const flow = await signInWithOtp(sag, { email: EMAIL });
  const { res, body } = await redeem(sag, { ...flow, extra: { client_secret: 'invented' } });
  assert.equal(res.status, 401);
  assert.match(body.error_description, /registered as public/);

  const emptyBasic = await sag.raw('/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: 'Basic ' + Buffer.from(DEV_CLIENT + ':').toString('base64'),
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      code_verifier: flow.verifier,
    }).toString(),
  });
  assert.equal(emptyBasic.status, 401, 'an empty Basic credential is still a credential');
});

test('two credentials at once are refused, because only one would be checked', async () => {
  const sag = createInstance({
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_APP_SECRET: 's3cret',
  });
  const flow = await signInWithOtp(sag, { email: EMAIL });
  const res = await sag.raw('/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: 'Basic ' + Buffer.from(DEV_CLIENT + ':s3cret').toString('base64'),
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: flow.authCode,
      redirect_uri: DEV_REDIRECT,
      code_verifier: flow.verifier,
      client_secret: 's3cret',
    }).toString(),
  });
  assert.equal(res.status, 401);
  assert.match((await res.json()).error_description, /exactly one client credential/);
});

test('private_key_jwt authentication works, and a bad assertion is refused', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const privateJwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), alg: 'ES256' };
  const kid = await jwkThumbprint(privateJwk);
  const publicJwk = publicPartOf({ ...privateJwk, kid });

  const sag = createInstance({
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_APP_JWKS: JSON.stringify({ keys: [publicJwk] }),
    CLIENT_APP_AUTH_METHOD: 'private_key_jwt',
    STATE_STORE_BACKEND: 'memory',
  });

  const assertion = async (overrides = {}) => {
    const now = nowSeconds();
    return signCompact(
      'ES256',
      pair.privateKey,
      { typ: 'JWT', kid },
      {
        iss: DEV_CLIENT,
        sub: DEV_CLIENT,
        aud: 'http://localhost:8787',
        jti: randomToken(12),
        iat: now,
        exp: now + 120,
        ...overrides,
      },
    );
  };

  const attempt = async (code, verifier, client_assertion) =>
    sag.raw('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: DEV_REDIRECT,
        client_id: DEV_CLIENT,
        code_verifier: verifier,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion,
      }).toString(),
    });

  // The happy path.
  const flow = await signInWithOtp(sag, { email: EMAIL });
  const usedAssertion = await assertion();
  const ok = await attempt(flow.authCode, flow.verifier, usedAssertion);
  assert.equal(ok.status, 200, JSON.stringify(await ok.clone().json()));

  sag.clearCookies();
  const replayFlow = await signInWithOtp(sag, { email: EMAIL });
  const replayed = await attempt(replayFlow.authCode, replayFlow.verifier, usedAssertion);
  assert.equal(replayed.status, 401);
  assert.match((await replayed.json()).error_description, /already been used/);

  // An assertion minted for a different identity provider must not work here.
  // Failed client authentication has not consumed replayFlow's code.
  const other = replayFlow;
  const wrongAud = await attempt(other.authCode, other.verifier, await assertion({ aud: 'https://another-idp.test' }));
  assert.equal(wrongAud.status, 401);
  assert.match((await wrongAud.json()).error_description, /not acceptable/);

  // A long-lived assertion is refused: it would stay replayable too long.
  const longLived = await attempt(
    other.authCode,
    other.verifier,
    await assertion({ exp: nowSeconds() + 4000 }),
  );
  assert.equal(longLived.status, 401);
  assert.match((await longLived.json()).error_description, /lifetime/);

  const missingIat = await attempt(other.authCode, other.verifier, await assertion({ iat: undefined }));
  assert.equal(missingIat.status, 401, 'omitting iat must not bypass the lifetime ceiling');
  assert.match((await missingIat.json()).error_description, /carry an iat/);

  // And one signed by a key the client never registered.
  const stranger = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const forged = await signCompact(
    'ES256',
    stranger.privateKey,
    { typ: 'JWT', kid },
    { iss: DEV_CLIENT, sub: DEV_CLIENT, aud: 'http://localhost:8787', jti: 'x', iat: nowSeconds(), exp: nowSeconds() + 60 },
  );
  const badSig = await attempt(other.authCode, other.verifier, forged);
  assert.equal(badSig.status, 401);
  assert.match((await badSig.json()).error_description, /signature/);
});

test('a JWK algorithm declaration constrains key selection even when kid matches', () => {
  const jwks = { keys: [{ kid: 'shared-rsa-key', use: 'sig', alg: 'RS256' }] };
  assert.throws(
    () => selectJwk(jwks, { kid: 'shared-rsa-key', alg: 'PS256' }),
    /no matching key/,
  );
});

test('remote JWKS reads require TLS and have a hard size limit', async (t) => {
  clearJwksCache();
  await assert.rejects(() => fetchJwks('http://keys.example.test/jwks'), /must use https/);

  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(
    JSON.stringify({ keys: [], padding: 'x'.repeat(270 * 1024) }),
    { headers: { 'content-type': 'application/json' } },
  );
  t.after(() => {
    globalThis.fetch = real;
    clearJwksCache();
  });
  await assert.rejects(
    () => fetchJwks('https://keys.example.test/jwks'),
    /larger than 262144 bytes/,
  );
});

// ---------------------------------------------------------------------------
// CIMD
// ---------------------------------------------------------------------------

/** Serve a client ID metadata document from a stubbed fetch. */
function serveCimd(doc, { status = 200, url = APP + '/client.json' } = {}) {
  const real = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (input) => {
    const target = typeof input === 'string' ? input : input.url;
    if (target !== url) throw new Error('unexpected fetch: ' + target);
    calls++;
    return new Response(typeof doc === 'string' ? doc : JSON.stringify(doc), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  };
  return {
    url,
    get calls() {
      return calls;
    },
    restore: () => {
      globalThis.fetch = real;
    },
  };
}

const cimdConfig = (env = {}) =>
  loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'x'.repeat(48),
    CLIENTS_CIMD_ENABLED: 'true',
    CLIENTS_CIMD_ALLOWED_DOMAINS: 'example.test',
    ...env,
  });

const PUBLIC_RESOLVER = {
  resolve: async (_hostname, type) => (type === 'A' ? ['93.184.216.34'] : []),
};

test('a CIMD document may describe a distinct client and localhost redirect URI', async (t) => {
  clearCimdCache();
  const stub = serveCimd({
    // A native application's public metadata can live separately from its
    // loopback listener. The document's optional client_id is not SAG's
    // client identifier - the metadata URL presented at /authorize is.
    client_id: 'http://localhost:3000',
    client_name: 'Example App',
    redirect_uris: ['http://localhost:3000/callback'],
  });
  t.after(() => {
    stub.restore();
    clearCimdCache();
  });

  const client = await resolveClient(cimdConfig(), stub.url, { resolver: PUBLIC_RESOLVER });
  assert.equal(client.source, 'cimd');
  assert.equal(client.clientName, 'Example App');
  assert.equal(client.tokenEndpointAuthMethod, 'none', 'no keys means a public client');
  assert.ok(client.requirePkce, 'a client that cannot be authenticated must use PKCE');
  assert.equal(client.clientId, stub.url);
  assert.ok(redirectUriAllowed(client, 'http://localhost:49152/callback'));
});

test('CIMD can be restricted to particular domains, with or without subdomains', async (t) => {
  clearCimdCache();
  const stub = serveCimd({ client_id: APP + '/client.json', redirect_uris: [APP + '/callback'] });
  t.after(() => {
    stub.restore();
    clearCimdCache();
  });

  await assert.rejects(
    () => resolveClient(cimdConfig({ CLIENTS_CIMD_ALLOWED_DOMAINS: 'trusted.test' }), stub.url, { resolver: PUBLIC_RESOLVER }),
    /does not accept client metadata from/,
  );

  clearCimdCache();
  const allowed = await resolveClient(cimdConfig({ CLIENTS_CIMD_ALLOWED_DOMAINS: 'example.test' }), stub.url, { resolver: PUBLIC_RESOLVER });
  assert.ok(allowed, 'app.example.test is a subdomain of example.test');

  clearCimdCache();
  await assert.rejects(
    () =>
      resolveClient(
        cimdConfig({ CLIENTS_CIMD_ALLOWED_DOMAINS: 'example.test', CLIENTS_CIMD_ALLOW_SUBDOMAINS: 'false' }),
        stub.url,
        { resolver: PUBLIC_RESOLVER },
      ),
    /does not accept client metadata from/,
  );
});

test('CIMD refuses literal and DNS-resolved private addresses outside development', async (t) => {
  clearCimdCache();
  const literal = serveCimd(
    { redirect_uris: ['https://app.example.test/callback'] },
    { url: 'https://127.0.0.1/client.json' },
  );
  t.after(() => {
    literal.restore();
    clearCimdCache();
  });
  await assert.rejects(
    () => resolveClient(cimdConfig({ CLIENTS_CIMD_ALLOWED_DOMAINS: '' }), literal.url),
    /public network address/,
  );
  assert.equal(literal.calls, 0, 'a private literal is rejected before fetch');

  const privateDns = {
    resolve: async (_hostname, type) => (type === 'A' ? ['93.184.216.34'] : ['fd00::7']),
  };
  await assert.rejects(
    () => resolveClient(cimdConfig({ CLIENTS_CIMD_ALLOWED_DOMAINS: '' }), APP + '/client.json', { resolver: privateDns }),
    /public network address/,
  );
  assert.equal(literal.calls, 0, 'a hostname with a private answer is rejected before fetch');
});

test('development CIMD may fetch localhost, but not an arbitrary private address', async (t) => {
  clearCimdCache();
  const localUrl = 'http://localhost/client.json';
  const stub = serveCimd({ redirect_uris: ['http://localhost/callback'] }, { url: localUrl });
  t.after(() => {
    stub.restore();
    clearCimdCache();
  });
  const dev = loadConfig({ SAG_ISSUER: 'http://localhost:8787', CLIENTS_CIMD_ENABLED: 'true' });
  assert.ok(await resolveClient(dev, localUrl));

  const privateUrl = 'http://10.0.0.7/client.json';
  await assert.rejects(() => resolveClient(dev, privateUrl), /public network address/);
});

test('an oversized CIMD document is refused rather than parsed', async (t) => {
  clearCimdCache();
  const big = JSON.stringify({
    client_id: APP + '/client.json',
    redirect_uris: [APP + '/callback'],
    padding: 'x'.repeat(40000),
  });
  const stub = serveCimd(big);
  t.after(stub.restore);

  await assert.rejects(
    () => resolveClient(cimdConfig(), stub.url, { resolver: PUBLIC_RESOLVER }),
    /larger than this deployment accepts/,
  );
});

test('CIMD is disabled when the operator turns it off', async (t) => {
  clearCimdCache();
  const stub = serveCimd({ client_id: APP + '/client.json', redirect_uris: [APP + '/callback'] });
  t.after(stub.restore);

  const client = await resolveClient(cimdConfig({ CLIENTS_CIMD_ENABLED: 'false' }), stub.url, { resolver: PUBLIC_RESOLVER });
  assert.equal(client, undefined);
  assert.equal(stub.calls, 0, 'and the document is not even fetched');
});

test('a CIMD document is cached rather than refetched', async (t) => {
  clearCimdCache();
  const stub = serveCimd({ client_id: APP + '/client.json', redirect_uris: [APP + '/callback'] });
  t.after(() => {
    stub.restore();
    clearCimdCache();
  });

  const config = cimdConfig();
  await resolveClient(config, stub.url, { resolver: PUBLIC_RESOLVER });
  await resolveClient(config, stub.url, { resolver: PUBLIC_RESOLVER });
  assert.equal(stub.calls, 1);
});

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

test('a public subject is stable and does not depend on the master secret', async () => {
  const base = { SAG_ISSUER: 'https://id.example.test', SUBJECT_SALT: 'never-rotate-this' };
  const a = loadConfig({ ...base, SAG_SECRET: 'a'.repeat(48) });
  const b = loadConfig({ ...base, SAG_SECRET: 'b'.repeat(48) });
  const client = { clientId: 'app', redirectUris: [APP + '/cb'] };

  assert.equal(a.subject.type, 'public', 'and it is the default');
  const first = await subjectFor(a, EMAIL, client);
  assert.equal(await subjectFor(b, EMAIL, client), first, 'rotating SAG_SECRET must not orphan accounts');
  assert.notEqual(first, EMAIL);

  // Every relying party sees the same value, which is the whole point.
  assert.equal(await subjectFor(a, EMAIL, { clientId: 'other', redirectUris: ['https://other.test/cb'] }), first);

  // Renaming the deployment does not orphan anybody either: a relying party
  // already separates two issuers by the `iss` it stores alongside the `sub`.
  const renamed = loadConfig({ ...base, SAG_ISSUER: 'https://other.example.test', SAG_SECRET: 'a'.repeat(48) });
  assert.equal(await subjectFor(renamed, EMAIL, client), first);

  // The salt is the only thing that is load bearing, and it is.
  const resalted = loadConfig({ ...base, SUBJECT_SALT: 'a-different-one', SAG_SECRET: 'a'.repeat(48) });
  assert.notEqual(await subjectFor(resalted, EMAIL, client), first);
});

test('a real deployment will not start without a salt to derive with', () => {
  const prod = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'a'.repeat(48),
    SIGNING_PRIVATE_JWK: '{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"c"}',
  });
  assert.ok(prod.problems.some((p) => /SUBJECT_SALT is not set/.test(p)));

  // In development it falls back rather than blocking the way, but says so.
  const dev = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  assert.deepEqual(dev.problems, []);
  assert.ok(dev.warnings.some((w) => /SUBJECT_SALT is not set; using the development salt/.test(w)));
});

test('an existing short subject salt warns but is not rejected or replaced', () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'a'.repeat(48),
    SUBJECT_SALT: 'short-salt',
  });
  assert.equal(config.subject.salt, 'short-salt');
  assert.ok(config.internalWarnings.some((warning) => /shorter than 16 characters/.test(warning)));
  assert.ok(!config.problems.some((problem) => /SUBJECT_SALT.*16/.test(problem)));
});

test('pairwise subjects differ per sector and need a salt', async () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'a'.repeat(48),
    SUBJECT_TYPE: 'pairwise',
    SUBJECT_SALT: 'never-rotate-this',
  });
  const one = { clientId: 'one', redirectUris: ['https://one.test/cb'] };
  const two = { clientId: 'two', redirectUris: ['https://two.test/cb'] };

  const subOne = await subjectFor(config, EMAIL, one);
  const subTwo = await subjectFor(config, EMAIL, two);
  assert.notEqual(subOne, subTwo, 'two relying parties must not be able to correlate');
  assert.equal(await subjectFor(config, EMAIL, one), subOne, 'but it must be stable');

  // A shared sector identifier is how relying parties opt into sharing one.
  const shared = { clientId: 'three', redirectUris: ['https://three.test/cb'], sectorIdentifier: 'group.test' };
  const alsoShared = { clientId: 'four', redirectUris: ['https://four.test/cb'], sectorIdentifier: 'group.test' };
  assert.equal(await subjectFor(config, EMAIL, shared), await subjectFor(config, EMAIL, alsoShared));

  // And without a salt it must refuse rather than fall back to something weak.
  const unsalted = { ...config, subject: { type: 'pairwise', salt: undefined } };
  await assert.rejects(() => subjectFor(unsalted, EMAIL, one), /SUBJECT_SALT/);
});

test('a sector is what a client declares, or its client id - never its redirect host', () => {
  assert.equal(sectorFor({ clientId: 'a', sectorIdentifier: 'Group.Test' }), 'group.test');
  assert.equal(
    sectorFor({ clientId: 'a', redirectUris: ['https://one.test/cb', 'https://one.test/other'] }),
    'client:a',
    'sharing an account is a decision, not something to infer from a hostname',
  );
  // And so a relying party that moves where it redirects keeps its accounts.
  assert.equal(
    sectorFor({ clientId: 'a', redirectUris: ['https://moved.test/cb'] }),
    sectorFor({ clientId: 'a', redirectUris: ['https://one.test/cb'] }),
  );
});

test('a pairwise deployment issues a pairwise sub in the id_token', async () => {
  const sag = createInstance({
    SUBJECT_TYPE: 'pairwise',
    SUBJECT_SALT: 'test-salt',
    CLIENT_APP_ID: 'pairwise-client',
    CLIENT_APP_REDIRECT_URIS: 'https://app.example.test/cb',
  });
  const flow = await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'pairwise-client', redirectUri: 'https://app.example.test/cb' },
  });
  const { body } = await redeem(sag, {
    ...flow,
    clientId: 'pairwise-client',
    redirectUri: 'https://app.example.test/cb',
  });
  const { body: jwks } = await sag.json('/jwks.json');
  const { header } = decodeJwt(body.id_token);
  const claims = await verifyCompact(body.id_token, jwks.keys.find((k) => k.kid === header.kid));

  const expected = await subjectFor(
    loadConfig({ SAG_ISSUER: 'http://localhost:8787', SAG_SECRET: 'x', SUBJECT_TYPE: 'pairwise', SUBJECT_SALT: 'test-salt' }),
    EMAIL,
    { clientId: 'pairwise-client', redirectUris: ['https://app.example.test/cb'] },
  );
  assert.equal(claims.sub, expected, 'the sub must be the pairwise derivation, not something else');
  assert.notEqual(claims.sub, EMAIL);
});

test('pairwise without a salt is a refusal to start, not a weak fallback', () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'a'.repeat(48),
    SUBJECT_TYPE: 'pairwise',
    EMAIL_PROVIDER: 'mailchannels',
    EMAIL_FROM: 'a@b.test',
  });
  assert.ok(config.problems.some((p) => /SUBJECT_SALT/.test(p)));
  assert.ok(config.problems.some((p) => /orphans every account/.test(p)), 'the reason must be stated');
});

// ---------------------------------------------------------------------------
// Session scope
// ---------------------------------------------------------------------------

test('per-RP sessions do not answer for another relying party', async () => {
  const sag = createInstance({
    SESSION_SCOPE: 'rp',
    CLIENT_ONE_ID: 'client-one',
    CLIENT_ONE_REDIRECT_URIS: 'https://one.test/cb',
    CLIENT_TWO_ID: 'client-two',
    CLIENT_TWO_REDIRECT_URIS: 'https://two.test/cb',
  });

  await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'client-one', redirectUri: 'https://one.test/cb' },
  });

  // The first client is now silent.
  const { challenge } = await pkce();
  const one = authorizeUrl({ challenge, clientId: 'client-one', redirectUri: 'https://one.test/cb', prompt: 'none' });
  const oneRes = await sag.raw(one.path);
  assert.equal(oneRes.status, 303);
  assert.ok(new URL(oneRes.headers.get('location')).searchParams.get('code'));

  // The second is not, because the session is scoped to the first.
  const two = authorizeUrl({ challenge, clientId: 'client-two', redirectUri: 'https://two.test/cb', prompt: 'none' });
  const twoRes = await sag.raw(two.path);
  assert.equal(twoRes.status, 303);
  assert.equal(new URL(twoRes.headers.get('location')).searchParams.get('error'), 'login_required');
});

test('a per-RP cookie name does not disclose which client it belongs to', async () => {
  const sag = createInstance({
    SESSION_SCOPE: 'rp',
    CLIENT_ONE_ID: 'a-recognisable-client-name',
    CLIENT_ONE_REDIRECT_URIS: 'https://one.test/cb',
  });
  await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'a-recognisable-client-name', redirectUri: 'https://one.test/cb' },
  });

  const names = [...sag.cookies.keys()];
  assert.equal(names.length, 1);
  assert.match(names[0], /^sag_session_[A-Za-z0-9]+$/);
  assert.ok(!names[0].includes('recognisable'), 'the cookie jar must not enumerate applications used');
});

test('a per-client RP scope overrides a shared instance cookie', async () => {
  const sag = createInstance({
    SESSION_SCOPE: 'shared',
    CLIENT_ONE_ID: 'client-one',
    CLIENT_ONE_REDIRECT_URIS: 'https://one.test/cb',
    CLIENT_ONE_SESSION_SCOPE: 'rp',
  });
  await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'client-one', redirectUri: 'https://one.test/cb' },
  });

  const names = [...sag.cookies.keys()];
  assert.equal(names.length, 1);
  assert.match(names[0], /^sag_session_[A-Za-z0-9]+$/, 'the override must not fall back to the shared cookie');
});

test('shared sessions answer for every relying party', async () => {
  const sag = createInstance({
    SESSION_SCOPE: 'shared',
    CLIENT_ONE_ID: 'client-one',
    CLIENT_ONE_REDIRECT_URIS: 'https://one.test/cb',
    CLIENT_TWO_ID: 'client-two',
    CLIENT_TWO_REDIRECT_URIS: 'https://two.test/cb',
  });
  await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'client-one', redirectUri: 'https://one.test/cb' },
  });

  const { challenge } = await pkce();
  const two = authorizeUrl({ challenge, clientId: 'client-two', redirectUri: 'https://two.test/cb', prompt: 'none' });
  const res = await sag.raw(two.path);
  assert.equal(res.status, 303);
  assert.ok(
    new URL(res.headers.get('location')).searchParams.get('code'),
    'that is the point of a shared session',
  );
});

// ---------------------------------------------------------------------------
// The client store
// ---------------------------------------------------------------------------

test('a client can come from a KV store, with a hashed secret', async () => {
  const digest = 'sha256:' + (await sha256hex('stored-secret'));
  const kv = {
    get: async (key) => {
      if (key !== 'clients/kv-client.json') return null;
      return {
        client_name: 'From KV',
        redirect_uris: ['https://kv.test/cb'],
        client_secret_digest: digest,
      };
    },
  };
  const sag = createInstance({ CLIENTS_STORE_BACKEND: 'cf-kv', SAG_CLIENTS: kv });

  const flow = await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'kv-client', redirectUri: 'https://kv.test/cb' },
  });

  const attempt = (secret) =>
    sag.raw('/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic ' + Buffer.from('kv-client:' + secret).toString('base64'),
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: flow.authCode,
        redirect_uri: 'https://kv.test/cb',
        code_verifier: flow.verifier,
      }).toString(),
    });

  assert.equal((await attempt('wrong')).status, 401);
  const ok = await attempt('stored-secret');
  assert.equal(ok.status, 200, JSON.stringify(await ok.clone().json()));
});

test('a client that does not exist yet is not cached as absent for long', async () => {
  // The case this exists for: a record added a moment ago, or an instance whose
  // very first lookup landed while the store was still being populated. A hit
  // cached for a minute is a stale record; a miss cached for a minute is a
  // relying party being told it does not exist.
  let record;
  const seen = [];
  const kv = {
    get: async (key) => {
      seen.push(key);
      return record ?? null;
    },
  };
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_STORE_BACKEND: 'cf-kv',
    CLIENTS_STORE_CACHE_TTL: '600',
  });
  const store = await createClientStore(config, { SAG_CLIENTS: kv });

  assert.equal(await store.get('late-arrival'), undefined);
  assert.equal(await store.get('late-arrival'), undefined);
  assert.equal(seen.length, 1, 'a repeated miss inside the window is still cached');

  // Ten seconds on, not ten minutes: the record is found without a restart.
  record = { redirect_uris: ['https://late.test/cb'] };
  const clock = Date;
  globalThis.Date = class extends clock {
    static now() {
      return clock.now() + 11_000;
    }
  };
  try {
    assert.equal((await store.get('late-arrival')).redirectUris[0], 'https://late.test/cb');
  } finally {
    globalThis.Date = clock;
  }

  // A hit, though, is held for the full time the operator asked for.
  assert.equal(seen.length, 2);
  await store.get('late-arrival');
  assert.equal(seen.length, 2, 'a hit is cached for CLIENTS_STORE_CACHE_TTL');
});

test('a store key that could escape its prefix is refused', async () => {
  const seen = [];
  const kv = {
    get: async (key) => {
      seen.push(key);
      return null;
    },
  };
  const sag = createInstance({ CLIENTS_STORE_BACKEND: 'cf-kv', SAG_CLIENTS: kv });

  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, clientId: '../../secrets/root' });
  const res = await sag.raw(path);
  assert.equal(res.status, 401, 'no such client');
  assert.deepEqual(seen, [], 'a traversal attempt must not reach the store at all');
});

test('an opaque store client is refused when opaque clients are turned off', async () => {
  // CLIENTS_OPAQUE_ENABLED was a dead flag until this test: read, advertised in
  // discovery, and enforced nowhere - so an operator who set it to false would
  // have believed they had turned something off.
  const kv = {
    get: async () => ({ redirect_uris: ['https://kv.test/cb'] }),
  };

  const on = createInstance({ CLIENTS_STORE_BACKEND: 'cf-kv', SAG_CLIENTS: kv });
  const allowed = await on.raw(
    authorizeUrl({ challenge: 'x'.repeat(43), clientId: 'a-guid-like-id', redirectUri: 'https://kv.test/cb' }).path,
  );
  assert.equal(allowed.status, 200, 'a bare identifier should resolve when opaque clients are allowed');

  const off = createInstance({
    CLIENTS_STORE_BACKEND: 'cf-kv',
    SAG_CLIENTS: kv,
    CLIENTS_OPAQUE_ENABLED: 'false',
  });
  const refused = await off.raw(
    authorizeUrl({ challenge: 'x'.repeat(43), clientId: 'a-guid-like-id', redirectUri: 'https://kv.test/cb' }).path,
  );
  assert.equal(refused.status, 401, 'and be refused when they are not');
});

test('turning opaque clients off leaves static and CIMD clients working', async (t) => {
  clearCimdCache();
  const kv = { get: async () => ({ redirect_uris: ['https://kv.test/cb'] }) };
  const stub = serveCimd({ client_id: APP + '/client.json', redirect_uris: [APP + '/callback'] });
  t.after(() => {
    stub.restore();
    clearCimdCache();
  });

  const config = cimdConfig({ CLIENTS_OPAQUE_ENABLED: 'false' });
  const store = { get: kv.get };

  // A statically configured client is explicit operator intent.
  config.clients.static.push({
    source: 'static',
    clientId: 'static-app',
    redirectUris: ['https://static.test/cb'],
    tokenEndpointAuthMethod: 'none',
  });
  const stat = await resolveClient(config, 'static-app', { store });
  assert.equal(stat?.source, 'static');

  // A self-describing client still works, because it is not opaque.
  const cimd = await resolveClient(config, stub.url, { store, resolver: PUBLIC_RESOLVER });
  assert.equal(cimd?.source, 'cimd');

  // But a bare identifier does not reach the store at all.
  const opaque = await resolveClient(config, 'a-guid-like-id', { store });
  assert.equal(opaque, undefined);
});
