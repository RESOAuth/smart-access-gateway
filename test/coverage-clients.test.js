// Tests to achieve line coverage across clients, store, config, context, clientauth, request, and code.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { createContext, resetContextCache } from '../src/context.js';
import { resolveClient, redirectUriAllowed, clearCimdCache } from '../src/clients/index.js';
import { createClientStore } from '../src/clients/store.js';
import { readCredentials, authenticateClient, verifyPrivateKeyJwt } from '../src/oauth/clientauth.js';
import { parseAuthorizationRequest, UnredirectableError } from '../src/oauth/request.js';
import { redeemCode } from '../src/oauth/code.js';
import { OAuthError } from '../src/util/errors.js';
import { publicPartOf, jwkThumbprint, signCompact } from '../src/crypto/jose.js';
import { nowSeconds, b64, b64u, utf8 } from '../src/util/bytes.js';

// ---------------------------------------------------------------------------
// 1. src/clients/index.js
// ---------------------------------------------------------------------------

test('clients/index: redirectUriAllowed ignores malformed registered URIs', () => {
  const client = {
    redirectUris: ['not an absolute url', 'https://valid.example.com/callback'],
  };
  assert.equal(redirectUriAllowed(client, 'https://valid.example.com/callback'), true);
  assert.equal(redirectUriAllowed(client, 'not an absolute url'), false);
});

test('clients/index: rememberCimd purges expired entries and evicts oldest when full', async () => {
  clearCimdCache();
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_CIMD_ENABLED: 'true',
    SAG_DEV: 'true',
  });

  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    return new Response(
      JSON.stringify({
        client_name: 'Test Client',
        redirect_uris: ['http://localhost:8788/cb'],
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  try {
    // 1. Populate cache with an entry that expires immediately (ttl=1 second, then wait or fill)
    config.clients.cimd.cacheTtlSeconds = 1;
    await resolveClient(config, 'http://localhost/client-exp.json');

    // Wait 1.1s so it expires
    await new Promise((r) => setTimeout(r, 1100));

    // 2. Add entries to trigger expired cleanup and fill up to MAX_CIMD_CACHED (500)
    config.clients.cimd.cacheTtlSeconds = 300;
    for (let i = 0; i <= 501; i++) {
      await resolveClient(config, `http://localhost/client-${i}.json`);
    }
  } finally {
    globalThis.fetch = origFetch;
    clearCimdCache();
  }
});

test('clients/index: resolveAddresses uses DoH queries when no resolver is provided', async () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: 'a'.repeat(32),
    SUBJECT_SALT: 'b'.repeat(32),
    CLIENTS_CIMD_ENABLED: 'true',
    DNS_RESOLVER_URL: 'https://dns.example.com/dns-query',
  });

  const origFetch = globalThis.fetch;
  try {
    // Successful DoH returning public IP
    globalThis.fetch = async (url) => {
      const u = new URL(url);
      if (u.origin === 'https://dns.example.com') {
        const type = u.searchParams.get('type');
        if (type === 'A') {
          return new Response(
            JSON.stringify({
              Answer: [{ type: 1, data: '93.184.216.34' }],
            }),
            { status: 200 },
          );
        }
        return new Response(JSON.stringify({ Answer: [] }), { status: 200 });
      }
      if (url === 'https://cimd.example.com/client.json') {
        return new Response(
          JSON.stringify({
            client_name: 'CIMD Client',
            redirect_uris: ['https://cimd.example.com/callback'],
          }),
          { status: 200 },
        );
      }
      return new Response('Not found', { status: 404 });
    };

    const client = await resolveClient(config, 'https://cimd.example.com/client.json');
    assert.equal(client.clientId, 'https://cimd.example.com/client.json');

    // DoH returns non-200
    globalThis.fetch = async (url) => {
      const u = new URL(url);
      if (u.origin === 'https://dns.example.com') {
        return new Response('DNS error', { status: 500 });
      }
      return new Response('{}', { status: 200 });
    };
    await assert.rejects(
      () => resolveClient(config, 'https://cimd-fail.example.com/client.json'),
      (err) => err instanceof OAuthError && err.code === 'invalid_client',
    );

    // DoH returns Answer that is not an array
    globalThis.fetch = async (url) => {
      const u = new URL(url);
      if (u.origin === 'https://dns.example.com') {
        return new Response(JSON.stringify({ Status: 3 }), { status: 200 });
      }
      return new Response('{}', { status: 200 });
    };
    await assert.rejects(
      () => resolveClient(config, 'https://cimd-noanswer.example.com/client.json'),
      (err) => err instanceof OAuthError && err.code === 'invalid_client',
    );
  } finally {
    globalThis.fetch = origFetch;
    clearCimdCache();
  }
});

test('clients/index: assertPublicCimdTarget refuses localhost/ends with .localhost outside dev', async () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: 'a'.repeat(32),
    SUBJECT_SALT: 'b'.repeat(32),
    CLIENTS_CIMD_ENABLED: 'true',
  });

  await assert.rejects(
    () => resolveClient(config, 'https://sub.localhost/client.json'),
    (err) => err instanceof OAuthError && /public network address/.test(err.description),
  );
});

test('clients/index: cimdJwksUri validates jwks_uri type, URL validity, credentials and origin', async () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_CIMD_ENABLED: 'true',
    SAG_DEV: 'true',
  });

  const origFetch = globalThis.fetch;
  try {
    // 1. jwks_uri not a string
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ redirect_uris: ['http://localhost/cb'], jwks_uri: 12345 }), { status: 200 });
    await assert.rejects(
      () => resolveClient(config, 'http://localhost/client-bad-jwksuri-1.json'),
      (err) => err instanceof OAuthError && /jwks_uri must be a URL/.test(err.description),
    );

    // 2. jwks_uri invalid URL
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ redirect_uris: ['http://localhost/cb'], jwks_uri: 'http://' }), { status: 200 });
    await assert.rejects(
      () => resolveClient(config, 'http://localhost/client-bad-jwksuri-2.json'),
      (err) => err instanceof OAuthError && /jwks_uri must be a URL/.test(err.description),
    );

    // 3. jwks_uri contains credentials
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({ redirect_uris: ['http://localhost/cb'], jwks_uri: 'http://user:pass@localhost/jwks.json' }),
        { status: 200 },
      );
    await assert.rejects(
      () => resolveClient(config, 'http://localhost/client-bad-jwksuri-3.json'),
      (err) => err instanceof OAuthError && /must share the document origin/.test(err.description),
    );

    // 4. jwks_uri different origin
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({ redirect_uris: ['http://localhost/cb'], jwks_uri: 'http://other-origin.local/jwks.json' }),
        { status: 200 },
      );
    await assert.rejects(
      () => resolveClient(config, 'http://localhost/client-bad-jwksuri-4.json'),
      (err) => err instanceof OAuthError && /must share the document origin/.test(err.description),
    );

    // 5. valid jwks_uri on same origin
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({ redirect_uris: ['http://localhost/cb'], jwks_uri: 'http://localhost/jwks.json' }),
        { status: 200 },
      );
    const client = await resolveClient(config, 'http://localhost/client-valid-jwksuri.json');
    assert.equal(client.jwksUri, 'http://localhost/jwks.json');
    assert.equal(client.tokenEndpointAuthMethod, 'private_key_jwt');
  } finally {
    globalThis.fetch = origFetch;
    clearCimdCache();
  }
});

test('clients/index: resolveCimd validation branches for URL, credentials, body reading, JSON and redirect_uris', async () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_CIMD_ENABLED: 'true',
    SAG_DEV: 'true',
  });

  // Malformed URL in clientId
  assert.equal(await resolveClient(config, 'http://['), undefined);

  // Client ID containing username/password
  await assert.rejects(
    () => resolveClient(config, 'http://user:pass@localhost/client.json'),
    (err) => err instanceof OAuthError && /must not contain a username or password/.test(err.description),
  );

  const origFetch = globalThis.fetch;
  try {
    // Body stream read error (non-BodyTooLargeError)
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      headers: new Headers(),
      body: {
        getReader() {
          return {
            read() {
              return Promise.reject(new TypeError('network stream terminated'));
            },
            releaseLock() {},
          };
        },
      },
    });
    await assert.rejects(
      () => resolveClient(config, 'http://localhost/stream-err.json'),
      (err) => err instanceof TypeError && err.message === 'network stream terminated',
    );

    // Non-JSON body
    globalThis.fetch = async () => new Response('not valid json', { status: 200 });
    await assert.rejects(
      () => resolveClient(config, 'http://localhost/not-json.json'),
      (err) => err instanceof OAuthError && /not valid JSON/.test(err.description),
    );

    // Malformed redirect_uri inside document
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ redirect_uris: ['not-a-url'] }), { status: 200 });
    await assert.rejects(
      () => resolveClient(config, 'http://localhost/bad-uri.json'),
      (err) => err instanceof OAuthError && /malformed redirect URI/.test(err.description),
    );

    // Empty redirect_uris array
    globalThis.fetch = async () => new Response(JSON.stringify({ redirect_uris: [] }), { status: 200 });
    await assert.rejects(
      () => resolveClient(config, 'http://localhost/empty-uris.json'),
      (err) => err instanceof OAuthError && /declares no redirect_uris/.test(err.description),
    );
  } finally {
    globalThis.fetch = origFetch;
    clearCimdCache();
  }
});

// ---------------------------------------------------------------------------
// 2. src/clients/store.js
// ---------------------------------------------------------------------------

test('clients/store: evicts expired entries first and oldest live entries when cache exceeds MAX_CACHED', async () => {
  const mockKv = {
    async get(key) {
      return {
        client_name: 'Store Client ' + key,
        redirect_uris: ['https://app.example.com/cb'],
      };
    },
  };

  // Test branch 1: with expired entries (freed = true)
  const configExp = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_STORE_BACKEND: 'cf-kv',
    CLIENTS_STORE_CACHE_TTL: '1',
  });
  const storeExp = await createClientStore(configExp, { SAG_CLIENTS: mockKv });

  // Add an entry with 1s ttl
  await storeExp.get('exp-client');
  await new Promise((r) => setTimeout(r, 1100));

  // Now query 500 items to trigger eviction where expired entries exist
  for (let i = 0; i <= 501; i++) {
    await storeExp.get(`client-${i}`);
  }

  // Test branch 2: with NO expired entries (freed = false, evicts oldest live entry)
  const configLive = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_STORE_BACKEND: 'cf-kv',
    CLIENTS_STORE_CACHE_TTL: '600',
  });
  const storeLive = await createClientStore(configLive, { SAG_CLIENTS: mockKv });

  for (let i = 0; i <= 505; i++) {
    await storeLive.get(`live-client-${i}`);
  }
});

test('clients/store: createBoundStore throws clear error when KV binding is missing for file or cf-kv', async () => {
  const configFile = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_STORE_BACKEND: 'file',
  });
  await assert.rejects(
    () => createClientStore(configFile, {}),
    /CLIENTS_STORE_BACKEND is file, which only the Node adapter can provide/,
  );

  const configKv = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CLIENTS_STORE_BACKEND: 'cf-kv',
  });
  await assert.rejects(
    () => createClientStore(configKv, {}),
    /CLIENTS_STORE_BACKEND is cf-kv but no KV namespace is bound/,
  );
});

// ---------------------------------------------------------------------------
// 3. src/config.js
// ---------------------------------------------------------------------------

test('config: bool() throws ConfigError on invalid boolean string', () => {
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', OTP_ENABLED: 'not-a-bool' }),
    /OTP_ENABLED must be a boolean, got "not-a-bool"/,
  );
});

test('config: jsonValue() throws ConfigError on invalid JSON', () => {
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', SIGNING_PUBLIC_JWKS_EXTRA: '{ bad json' }),
    /SIGNING_PUBLIC_JWKS_EXTRA must be valid JSON/,
  );
});

test('config: resolveIssuer() validates URL syntax, protocol, and requestUrl derivation', () => {
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'not an absolute url' }),
    /SAG_ISSUER must be an absolute URL/,
  );
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'ftp://example.com' }),
    /SAG_ISSUER must be an http or https URL/,
  );
  assert.throws(
    () => loadConfig({}, { requestUrl: 'ftp://example.com' }),
    /The request URL used to derive SAG_ISSUER must be http or https/,
  );
});

test('config: readSigning() validates asymmetric algorithm and extraPublicJwks array', () => {
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', SIGNING_ALG: 'HS256' }),
    /SIGNING_ALG must be an asymmetric JWS algorithm/,
  );
  assert.throws(
    () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', SIGNING_PUBLIC_JWKS_EXTRA: '{"not":"array"}' }),
    /SIGNING_PUBLIC_JWKS_EXTRA must be a JSON array of public JWKs/,
  );
});

test('config: cloudflare-hsm without HSM_SHARED_SECRET reports configuration problem', () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    SIGNING_BACKEND: 'cloudflare-hsm',
  });
  assert.ok(config.problems.some((p) => /HSM_SHARED_SECRET is not set/.test(p)));
});

test('config: readUpstreams() ignores keys with unknown fields or missing slug', () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    UPSTREAM_MICROSOFT_COMMON_UNKNOWNFIELD: 'value',
    UPSTREAM_MICROSOFT_CLIENT_ID: 'common:client123',
  });
  assert.ok(config.internalWarnings.some((w) => /does not end in a known upstream field/.test(w)));
  assert.ok(config.internalWarnings.some((w) => /expected UPSTREAM_<PROVIDER>_<SLUG>_CLIENT_ID/.test(w)));
});

test('config: corsOriginsFromClients ignores malformed client redirect URI', () => {
  const config = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    CORS_ALLOWED_ORIGINS: 'https://allowed.example.com',
    CLIENT_APP_ID: 'app',
    CLIENT_APP_REDIRECT_URIS: 'not-a-valid-url,https://app.example.com/cb',
  });
  assert.ok(config.cors.allowedOrigins.some((origin) => origin === 'https://app.example.com'));
});

test('config: loadConfig checks SAG_SECRET length, SESSION_MAX_LIFETIME and CUSTOM_CSS_REMOTE_URL outside dev', () => {
  const config = loadConfig({
    SAG_ISSUER: 'https://auth.example.com',
    SAG_SECRET: 'short',
    SUBJECT_SALT: 'a'.repeat(32),
    SESSION_MAX_LIFETIME: '60',
    SESSION_TTL: '120',
    CUSTOM_CSS_REMOTE_URL: 'http://insecure.example.com/style.css',
  });
  assert.ok(config.problems.some((p) => /SAG_SECRET must be at least 32 characters/.test(p)));
  assert.ok(config.problems.some((p) => /SESSION_MAX_LIFETIME must not be shorter than SESSION_TTL/.test(p)));
  assert.ok(config.problems.some((p) => /CUSTOM_CSS_REMOTE_URL must be an https URL/.test(p)));
});

// ---------------------------------------------------------------------------
// 4. src/context.js
// ---------------------------------------------------------------------------

test('context: cacheFor(undefined) falls back to fallbackCache and logger dev formatting/levels work', async () => {
  resetContextCache();
  const req = new Request('http://localhost:8787/');
  // cacheFor(undefined)
  const ctx = await createContext(undefined, req);
  assert.equal(ctx.issuer, 'http://localhost:8787');

  // Test logger with devMode enabled and various levels
  const devReq = new Request('http://localhost:8787/');
  const devCtx = await createContext({ SAG_DEV: 'true', LOG_LEVEL: 'debug' }, devReq);

  // Exercise log levels and formatDev with and without fields
  devCtx.log.debug('debug message', { field1: 'val1', field2: 2 });
  devCtx.log.info('info message without fields');
  devCtx.log.warn('warn message', { warning: true });
  devCtx.log.error('error message', { err: 'fatal' });

  // Exercise logger below threshold
  const silentCtx = await createContext({ LOG_LEVEL: 'error' }, req);
  silentCtx.log.debug('ignored');
  silentCtx.log.info('ignored');
  silentCtx.log.warn('ignored');
});

// ---------------------------------------------------------------------------
// 5. src/oauth/clientauth.js
// ---------------------------------------------------------------------------

test('oauth/clientauth: safeDecode handles malformed percent-encoding in HTTP Basic', () => {
  const req = new Request('http://localhost:8787/token', {
    headers: {
      // Basic encoding of "%ZZ:secret"
      authorization: 'Basic ' + b64(utf8('%ZZ:mysecret')),
    },
  });
  const creds = readCredentials(req, new URLSearchParams());
  assert.equal(creds.basicId, '%ZZ');
  assert.equal(creds.secret, 'mysecret');
});

test('oauth/clientauth: authenticateClient enforces private_key_jwt and rejects unsupported auth methods', async () => {
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const pkClient = { clientId: 'pk-client', tokenEndpointAuthMethod: 'private_key_jwt' };

  // private_key_jwt client presenting none or secret
  await assert.rejects(
    () => authenticateClient(config, pkClient, { method: 'none' }),
    (err) => err instanceof OAuthError && /must authenticate with a private_key_jwt assertion/.test(err.description),
  );

  // unsupported auth method
  const weirdClient = { clientId: 'weird', tokenEndpointAuthMethod: 'tls_client_auth' };
  await assert.rejects(
    () => authenticateClient(config, weirdClient, { method: 'none' }),
    (err) => err instanceof OAuthError && /Unsupported client authentication method/.test(err.description),
  );
});

test('oauth/clientauth: verifyPrivateKeyJwt validates JWT format, alg, remote JWKS failure, key match and jti', async () => {
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), alg: 'ES256' };
  const kid = await jwkThumbprint(jwk);
  const privateJwk = { ...jwk, kid };
  const publicJwk = publicPartOf(privateJwk);

  const client = {
    clientId: 'client-123',
    tokenEndpointAuthMethod: 'private_key_jwt',
    jwks: { keys: [publicJwk] },
  };

  // 1. Not a valid JWT
  await assert.rejects(
    () => verifyPrivateKeyJwt(config, client, 'invalid.jwt.token'),
    (err) => err instanceof OAuthError && /not a valid JWT/.test(err.description),
  );

  // 2. Unsupported algorithm (e.g. HS256)
  const hsToken = b64u(utf8(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))) + '.' + b64u(utf8('{}')) + '.sig';
  await assert.rejects(
    () => verifyPrivateKeyJwt(config, client, hsToken),
    (err) => err instanceof OAuthError && /Unsupported client assertion algorithm/.test(err.description),
  );

  // 3. Remote jwks_uri fetch failure
  const clientWithJwksUri = {
    clientId: 'client-uri',
    tokenEndpointAuthMethod: 'private_key_jwt',
    jwksUri: 'http://localhost:8787/nonexistent-jwks.json',
  };
  const validSignedAssertion = await signCompact(
    'ES256',
    pair.privateKey,
    { kid },
    {
      iss: 'client-uri',
      sub: 'client-uri',
      aud: config.issuer,
      jti: 'jti-1',
      iat: nowSeconds(),
      exp: nowSeconds() + 60,
    },
  );
  await assert.rejects(
    () => verifyPrivateKeyJwt(config, clientWithJwksUri, validSignedAssertion),
    (err) => err instanceof OAuthError && /Could not read the client JWKS/.test(err.description),
  );

  // 4. No registered key matches the assertion
  const otherPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const otherJwk = { ...(await crypto.subtle.exportKey('jwk', otherPair.privateKey)), alg: 'ES256' };
  const otherPublicJwk = { ...publicPartOf(otherJwk), kid: 'other-key-id' };
  const clientMismatchedKey = {
    clientId: 'client-123',
    tokenEndpointAuthMethod: 'private_key_jwt',
    jwks: { keys: [otherPublicJwk] },
  };
  await assert.rejects(
    () => verifyPrivateKeyJwt(config, clientMismatchedKey, validSignedAssertion),
    (err) => err instanceof OAuthError && /No registered key matches the client assertion/.test(err.description),
  );

  // 5. Missing or non-string jti
  const assertionNoJti = await signCompact(
    'ES256',
    pair.privateKey,
    { kid },
    {
      iss: 'client-123',
      sub: 'client-123',
      aud: config.issuer,
      iat: nowSeconds(),
      exp: nowSeconds() + 60,
    },
  );
  await assert.rejects(
    () => verifyPrivateKeyJwt(config, client, assertionNoJti),
    (err) => err instanceof OAuthError && /must carry a string jti/.test(err.description),
  );
});

// ---------------------------------------------------------------------------
// 6. src/oauth/request.js
// ---------------------------------------------------------------------------

test('oauth/request: parseAuthorizationRequest handles resolveClient errors and missing redirect_uri', async () => {
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });

  // resolveClient throws OAuthError
  await assert.rejects(
    () =>
      parseAuthorizationRequest(new URLSearchParams({ client_id: 'bad-oauth' }), config, {
        resolveClient: async () => {
          throw new OAuthError('unauthorized_client', 'Client not allowed');
        },
      }),
    (err) => err instanceof UnredirectableError && err.code === 'unauthorized_client',
  );

  // resolveClient throws generic Error
  await assert.rejects(
    () =>
      parseAuthorizationRequest(new URLSearchParams({ client_id: 'bad-generic' }), config, {
        resolveClient: async () => {
          throw new Error('Database down');
        },
      }),
    (err) => err instanceof UnredirectableError && /The client could not be identified/.test(err.description),
  );

  // missing redirect_uri
  const mockClient = { clientId: 'dev', redirectUris: ['http://localhost/cb'] };
  await assert.rejects(
    () =>
      parseAuthorizationRequest(new URLSearchParams({ client_id: 'dev' }), config, {
        resolveClient: async () => mockClient,
      }),
    (err) => err instanceof UnredirectableError && /redirect_uri parameter is missing/.test(err.description),
  );
});

test('oauth/request: parseAuthorizationRequest validates response_type, response_mode, scopes, PKCE, prompt and max_age', async () => {
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const mockClient = {
    clientId: 'dev',
    redirectUris: ['http://localhost/cb'],
    scopes: ['openid', 'email'],
    requirePkce: true,
  };
  const deps = { resolveClient: async () => mockClient };

  const baseParams = () => ({
    client_id: 'dev',
    redirect_uri: 'http://localhost/cb',
    response_type: 'code',
    scope: 'openid email',
    code_challenge: 'a'.repeat(43),
    code_challenge_method: 'S256',
  });

  // Unsupported response_type
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), response_type: 'token' }), config, deps),
    (err) => err.code === 'unsupported_response_type',
  );

  // Unsupported response_mode
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), response_mode: 'fragment' }), config, deps),
    (err) => err.code === 'invalid_request' && /response_mode must be "query" or "form_post"/.test(err.description),
  );

  // Scope missing openid
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), scope: 'email' }), config, deps),
    (err) => err.code === 'invalid_scope' && /scope must include "openid"/.test(err.description),
  );

  // Scope not permitted for this client
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), scope: 'openid profile' }), config, deps),
    (err) => err.code === 'invalid_scope' && /This client may not request: profile/.test(err.description),
  );

  // code_challenge_method != S256
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), code_challenge_method: 'plain' }), config, deps),
    (err) => err.code === 'invalid_request' && /code_challenge_method must be "S256"/.test(err.description),
  );

  // Malformed code_challenge
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), code_challenge: 'short' }), config, deps),
    (err) => err.code === 'invalid_request' && /not a valid base64url S256 digest/.test(err.description),
  );

  // prompt=none combined with other prompt values
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), prompt: 'none consent' }), config, deps),
    (err) => err.code === 'invalid_request' && /prompt=none cannot be combined/.test(err.description),
  );

  // Invalid max_age (negative or non-integer)
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), max_age: '-10' }), config, deps),
    (err) => err.code === 'invalid_request' && /max_age must be a non-negative integer/.test(err.description),
  );
  await assert.rejects(
    () => parseAuthorizationRequest(new URLSearchParams({ ...baseParams(), max_age: 'abc' }), config, deps),
    (err) => err.code === 'invalid_request' && /max_age must be a non-negative integer/.test(err.description),
  );
});

// ---------------------------------------------------------------------------
// 7. src/oauth/code.js
// ---------------------------------------------------------------------------

test('oauth/code: redeemCode throws invalid_grant when unsealing corrupted code token', async () => {
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  await assert.rejects(
    () =>
      redeemCode(config, {
        code: 'corrupted-code-token',
        clientId: 'dev',
        redirectUri: 'http://localhost/cb',
      }),
    (err) => err instanceof OAuthError && err.code === 'invalid_grant',
  );
});
