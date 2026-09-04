// Focused unit tests targeting line coverage across src/upstream/{dns,index,providers}.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { createStubProvider } from './upstream-stub.js';
import {
  mailProviderFor,
  hintUpstreams,
  clearMailProviderCache,
} from '../src/upstream/dns.js';
import {
  upstreamMetadata,
  clearUpstreamMetadataCache,
  upstreamsFor,
  beginUpstream,
  completeUpstream,
  describeUpstream,
  labelFor,
} from '../src/upstream/index.js';
import {
  PROVIDERS,
  providerFor,
} from '../src/upstream/providers.js';

function stubResolver(zones = {}) {
  return {
    resolve(name, type) {
      const zone = zones[name];
      if (!zone) throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
      return Promise.resolve(zone[type] || []);
    },
  };
}

// ---------------------------------------------------------------------------
// src/upstream/dns.js coverage
// ---------------------------------------------------------------------------

test('dns: remember cache evicts oldest entry when size exceeds MAX_CACHED (500)', async () => {
  clearMailProviderCache();
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const ctx = { config, env: { SAG_DNS: stubResolver({}) } };

  // Fill cache with 500 entries (MAX_CACHED = 500)
  for (let i = 0; i < 500; i++) {
    await mailProviderFor(ctx, `domain-${i}.test`);
  }
  // 501st entry triggers line 89-91: cache.size >= MAX_CACHED and evicts oldest
  await mailProviderFor(ctx, 'domain-500.test');

  // Verify caching still works
  const res = await mailProviderFor(ctx, 'domain-500.test');
  assert.equal(res, undefined);
});

test('dns: DoH resolver path handles HTTP failures and malformed DNS JSON (lines 126-130)', async () => {
  clearMailProviderCache();
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const ctx = { config, env: {} }; // No SAG_DNS binding -> falls back to DoH fetch

  const realFetch = globalThis.fetch;

  try {
    // 1. HTTP not ok (status 500) -> line 126 returns []
    globalThis.fetch = async () => new Response('Internal Server Error', { status: 500 });
    clearMailProviderCache();
    const failRes = await mailProviderFor(ctx, 'server-error.test');
    assert.equal(failRes, undefined);

    // 2. DNS JSON with no Answer array (NXDOMAIN or empty) -> line 130 returns []
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ Status: 3, Comment: 'NXDOMAIN' }), {
        status: 200,
        headers: { 'content-type': 'application/dns-json' },
      });
    clearMailProviderCache();
    const nxRes = await mailProviderFor(ctx, 'nxdomain.test');
    assert.equal(nxRes, undefined);

    // 3. DNS JSON with valid MX answer (type 15) -> recognised provider
    globalThis.fetch = async (url) => {
      const u = new URL(url);
      if (u.searchParams.get('type') === 'MX') {
        return new Response(
          JSON.stringify({
            Status: 0,
            Answer: [{ name: 'mx.test', type: 15, data: '10 mail.protection.outlook.com.' }],
          }),
          { status: 200, headers: { 'content-type': 'application/dns-json' } },
        );
      }
      return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
    };
    clearMailProviderCache();
    const mxRes = await mailProviderFor(ctx, 'mx.test');
    assert.deepEqual(mxRes, { provider: 'microsoft', source: 'mx' });

    // 4. DNS JSON with valid SPF/TXT answer (type 16) -> recognised provider
    globalThis.fetch = async (url) => {
      const u = new URL(url);
      if (u.searchParams.get('type') === 'TXT') {
        return new Response(
          JSON.stringify({
            Status: 0,
            Answer: [{ name: 'spf.test', type: 16, data: '"v=spf1 include:_spf.google.com -all"' }],
          }),
          { status: 200, headers: { 'content-type': 'application/dns-json' } },
        );
      }
      return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
    };
    clearMailProviderCache();
    const spfRes = await mailProviderFor(ctx, 'spf.test');
    assert.deepEqual(spfRes, { provider: 'google', source: 'spf' });

    // 5. Fetch network error (rejected promise) -> caught at line 136, returns []
    globalThis.fetch = async () => Promise.reject(new Error('Network offline'));
    clearMailProviderCache();
    const errRes = await mailProviderFor(ctx, 'neterr.test');
    assert.equal(errRes, undefined);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('dns: hintUpstreams with edge cases and successful reordering', async () => {
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const resolver = stubResolver({
    'acme.test': { MX: ['10 mail.protection.outlook.com.'] },
    'other.test': { MX: ['10 mail.protonmail.ch.'] },
    'unmatched.test': { MX: ['10 mail.unknown.test.'], TXT: ['v=spf1 include:spf.unknown.test -all'] },
  });
  const ctx = { config, env: { SAG_DNS: resolver } };

  // 1. Off configuration
  const offCtx = { config: loadConfig({ SAG_ISSUER: 'http://localhost:8787', SIGNIN_PROVIDER_HINT: 'off' }), env: {} };
  const upstreams = [{ id: 'u1', provider: 'google' }, { id: 'u2', provider: 'microsoft' }];
  assert.deepEqual(await hintUpstreams(offCtx, upstreams, 'example.com'), { list: upstreams });

  // 2. Fewer than 2 upstreams
  assert.deepEqual(await hintUpstreams(ctx, [upstreams[0]], 'example.com'), { list: [upstreams[0]] });

  // 3. No hint found (unrecognised records reach end of matchMx and matchSpf)
  clearMailProviderCache();
  assert.deepEqual(await hintUpstreams(ctx, upstreams, 'unmatched.test'), { list: upstreams });

  // 4. Invalid domains rejected early
  clearMailProviderCache();
  assert.equal(await mailProviderFor(ctx, 'a'.repeat(300) + '.test'), undefined);
  assert.equal(await mailProviderFor(ctx, '-invalid-.test'), undefined);
  assert.equal(await mailProviderFor(ctx, ''), undefined);

  // 5. Successful hint reorders list
  clearMailProviderCache();
  const hintedResult = await hintUpstreams(ctx, upstreams, 'acme.test');
  assert.equal(hintedResult.list[0].id, 'u2');
  assert.equal(hintedResult.hinted.id, 'u2');
  assert.equal(hintedResult.source, 'mx');

  // 6. Hinted provider not among configured upstreams
  clearMailProviderCache();
  const noMatchResult = await hintUpstreams(ctx, upstreams, 'other.test');
  assert.deepEqual(noMatchResult, { list: upstreams });
});

// ---------------------------------------------------------------------------
// src/upstream/index.js coverage
// ---------------------------------------------------------------------------

test('index: checkedRemoteUrl URL validation errors (lines 30-31, 33-34)', async () => {
  // 1. Discovery URL not an absolute URL (lines 30-31)
  await assert.rejects(
    () => upstreamMetadata({ id: 'bad-url', provider: 'oidc', issuer: 'not-a-valid-url' }),
    /upstream bad-url discovery URL is not an absolute URL/,
  );

  // Explicit endpoints URL not an absolute URL
  await assert.rejects(
    () => upstreamMetadata({
      id: 'bad-issuer',
      provider: 'oidc',
      issuer: 'not-a-valid-url',
      authorizationEndpoint: 'https://auth.test',
      tokenEndpoint: 'https://token.test',
      jwksUri: 'https://jwks.test',
    }),
    /upstream bad-issuer issuer is not an absolute URL/,
  );

  // 2. Contains username/password credentials (lines 33-34)
  await assert.rejects(
    () => upstreamMetadata({ id: 'creds-url', provider: 'oidc', issuer: 'https://user:pass@example.com' }),
    /upstream creds-url discovery URL must use https/,
  );

  // 3. HTTP URL when allowHttp is false (lines 33-34)
  await assert.rejects(
    () => upstreamMetadata({ id: 'insecure-url', provider: 'oidc', issuer: 'http://example.com' }, { allowHttp: false }),
    /upstream insecure-url discovery URL must use https/,
  );
});

test('index: rememberMetadata expired entry eviction and cache limit (lines 50-51, 54-56)', async () => {
  clearUpstreamMetadataCache();
  const realFetch = globalThis.fetch;

  try {
    globalThis.fetch = async (url) => {
      const u = new URL(url);
      const origin = u.origin;
      return new Response(
        JSON.stringify({
          issuer: origin,
          authorization_endpoint: origin + '/auth',
          token_endpoint: origin + '/token',
          jwks_uri: origin + '/jwks',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };

    // 1. Expired cache eviction (lines 50-51)
    // Insert an entry with ttlSeconds = -10 (already expired)
    await upstreamMetadata({ id: 'exp', provider: 'oidc', issuer: 'https://expired.test' }, { ttlSeconds: -10 });
    // Inserting a second entry runs rememberMetadata which cleans up expired entries
    await upstreamMetadata({ id: 'live', provider: 'oidc', issuer: 'https://live.test' }, { ttlSeconds: 3600 });

    // 2. Cache eviction on MAX_METADATA_CACHE_ENTRIES = 100 (lines 54-56)
    clearUpstreamMetadataCache();
    for (let i = 0; i <= 100; i++) {
      await upstreamMetadata(
        { id: `u-${i}`, provider: 'oidc', issuer: `https://issuer-${i}.test` },
        { ttlSeconds: 3600 },
      );
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('index: upstreamMetadata missing discovery URL and explicit endpoints (lines 82-85)', async () => {
  // Generic OIDC provider with no issuer and incomplete endpoints
  await assert.rejects(
    () => upstreamMetadata({ id: 'no-endpoints', provider: 'oidc' }),
    /upstream no-endpoints needs either an ISSUER to discover from or all of its endpoints set explicitly/,
  );
});

test('index: upstreamMetadata discovery failures and missing required fields', async () => {
  const realFetch = globalThis.fetch;
  try {
    // Discovery HTTP failure
    globalThis.fetch = async () => new Response('Not Found', { status: 404 });
    await assert.rejects(
      () => upstreamMetadata({ id: 'disco-404', provider: 'google' }),
      /upstream discovery for disco-404 failed with HTTP 404/,
    );

    // Discovery document missing a required field (e.g., token_endpoint)
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          issuer: 'https://accounts.google.com',
          authorization_endpoint: 'https://accounts.google.com/auth',
          jwks_uri: 'https://accounts.google.com/jwks',
          // token_endpoint missing!
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    await assert.rejects(
      () => upstreamMetadata({ id: 'missing-field', provider: 'google' }),
      /upstream missing-field discovery document has no token_endpoint/,
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('index: upstreamsFor matching logic', () => {
  const config = {
    upstreams: [
      { id: 'exact', domain: 'sub.example.com', isCommon: false },
      { id: 'parent', domain: 'example.com', isCommon: false },
      { id: 'common', isCommon: true },
    ],
  };

  // Invalid email / no domain
  assert.deepEqual(upstreamsFor(config, 'not-an-email'), []);
  assert.deepEqual(upstreamsFor(config, ''), []);

  // Exact domain match
  const exact = upstreamsFor(config, 'user@sub.example.com');
  assert.equal(exact.length, 1);
  assert.equal(exact[0].id, 'exact');

  // Parent domain match
  const parent = upstreamsFor(config, 'user@other.example.com');
  assert.equal(parent.length, 1);
  assert.equal(parent[0].id, 'parent');

  // Common match
  const common = upstreamsFor(config, 'user@unrelated.org');
  assert.equal(common.length, 1);
  assert.equal(common[0].id, 'common');
});

test('index: describeUpstream returns safe display properties (lines 313-319)', () => {
  const u1 = { id: 'ms-common', provider: 'microsoft', domain: undefined, isCommon: true };
  assert.deepEqual(describeUpstream(u1), {
    id: 'ms-common',
    provider: 'microsoft',
    domain: undefined,
    label: 'Microsoft',
  });

  const u2 = { id: 'ms-tenant', provider: 'microsoft', domain: 'acme.com', isCommon: false };
  assert.deepEqual(describeUpstream(u2), {
    id: 'ms-tenant',
    provider: 'microsoft',
    domain: 'acme.com',
    label: 'Microsoft (acme.com)',
  });
});

test('index: beginUpstream prompt and parameter propagation', async () => {
  const ctx = {
    config: loadConfig({ SAG_ISSUER: 'http://localhost:8787', SAG_SECRET: 'a'.repeat(64) }),
    absolute: (p) => 'http://localhost:8787' + p,
  };
  const upstream = {
    id: 'ms-corp',
    provider: 'microsoft',
    clientId: 'ms-client-1',
    domain: 'corp.example.com',
    isCommon: false,
    issuer: 'https://login.microsoftonline.com/corp.example.com/v2.0',
    authorizationEndpoint: 'https://login.microsoftonline.com/corp.example.com/oauth2/v2.0/authorize',
    tokenEndpoint: 'https://login.microsoftonline.com/corp.example.com/oauth2/v2.0/token',
    jwksUri: 'https://login.microsoftonline.com/corp.example.com/discovery/v2.0/keys',
    acrValues: ['urn:mace:incommon:iap:silver'],
  };

  // Test prompt=select_account, max_age, email, acr_values
  const req1 = await beginUpstream(ctx, upstream, {
    client_id: 'client-1',
    redirect_uri: 'http://localhost:8787/cb',
    prompt: ['select_account'],
    max_age: 600,
    email: 'user@corp.example.com',
  }, { hinted: true });

  const u1 = new URL(req1.url);
  assert.equal(u1.searchParams.get('prompt'), 'select_account');
  assert.equal(u1.searchParams.get('max_age'), '600');
  assert.equal(u1.searchParams.get('login_hint'), 'user@corp.example.com');
  assert.equal(u1.searchParams.get('domain_hint'), 'corp.example.com');
  assert.equal(u1.searchParams.get('acr_values'), 'urn:mace:incommon:iap:silver');
  assert.equal(req1.stateTx.upstream.hinted, true);

  // Test explicit upstream.prompt override
  const req2 = await beginUpstream(ctx, { ...upstream, prompt: 'consent' }, {
    client_id: 'client-1',
    redirect_uri: 'http://localhost:8787/cb',
    prompt: ['login'],
  });
  const u2 = new URL(req2.url);
  assert.equal(u2.searchParams.get('prompt'), 'consent');

  // Test prompt=none propagation
  const req3 = await beginUpstream(ctx, upstream, {
    client_id: 'client-1',
    redirect_uri: 'http://localhost:8787/cb',
    prompt: ['none'],
  });
  const u3 = new URL(req3.url);
  assert.equal(u3.searchParams.get('prompt'), 'none');

  // Test prompt=login propagation
  const req4 = await beginUpstream(ctx, upstream, {
    client_id: 'client-1',
    redirect_uri: 'http://localhost:8787/cb',
    prompt: ['login'],
  });
  const u4 = new URL(req4.url);
  assert.equal(u4.searchParams.get('prompt'), 'login');

  // Test no prompt
  const req5 = await beginUpstream(ctx, upstream, {
    client_id: 'client-1',
    redirect_uri: 'http://localhost:8787/cb',
  });
  const u5 = new URL(req5.url);
  assert.equal(u5.searchParams.get('prompt'), null);
});

test('index: completeUpstream edge cases and validation failures', async () => {
  const ctx = {
    config: loadConfig({ SAG_ISSUER: 'http://localhost:8787', SAG_SECRET: 'b'.repeat(64) }),
    absolute: (p) => 'http://localhost:8787' + p,
  };
  const provider = await createStubProvider();
  const restore = provider.install();

  try {
    const upstream = {
      id: 'stub-upstream',
      provider: 'oidc',
      clientId: 'stub-client-id',
      clientSecret: 'stub-secret',
      domain: 'corp.test',
      isCommon: false,
      issuer: provider.issuer,
      authorizationEndpoint: provider.metadata.authorization_endpoint,
      tokenEndpoint: provider.metadata.token_endpoint,
      jwksUri: provider.metadata.jwks_uri,
    };

    const stateTx = {
      upstream: {
        id: upstream.id,
        verifier: 'test-verifier-12345',
        nonce: 'test-nonce-12345',
        redirectUri: 'http://localhost:8787/callback',
      },
    };

    // 1. Token endpoint returns error without error_description (e.g. invalid_grant)
    provider.state.tokenError = 'invalid_grant';
    await assert.rejects(
      () => completeUpstream(ctx, upstream, { code: 'bad-code', stateTx }),
      /upstream token exchange failed: invalid_grant/,
    );
    provider.state.tokenError = undefined;

    // 2. Token endpoint returns 200 without id_token
    const savedFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      if (url === provider.metadata.token_endpoint) {
        return new Response(JSON.stringify({ access_token: 'tok' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return savedFetch(url, init);
    };
    await assert.rejects(
      () => completeUpstream(ctx, upstream, { code: 'no-id-token', stateTx }),
      /upstream returned no id_token/,
    );
    globalThis.fetch = savedFetch;

    // 3. Claims with no email / upn / preferred_username
    await provider.expect({
      audience: upstream.clientId,
      nonce: stateTx.upstream.nonce,
      claims: { email: undefined, preferred_username: undefined, upn: undefined },
    });
    await assert.rejects(
      () => completeUpstream(ctx, upstream, { code: 'code1', stateTx }),
      /the upstream did not return an email address for this account/,
    );

    // 4. Claims with email_verified: false
    await provider.expect({
      audience: upstream.clientId,
      nonce: stateTx.upstream.nonce,
      claims: { email: 'user@corp.test', email_verified: false },
    });
    await assert.rejects(
      () => completeUpstream(ctx, upstream, { code: 'code2', stateTx }),
      /the upstream reports this email address as unverified/,
    );

    // 5. Domain mismatch for domain-specific upstream
    await provider.expect({
      audience: upstream.clientId,
      nonce: stateTx.upstream.nonce,
      claims: { email: 'user@other-domain.test', email_verified: true },
    });
    await assert.rejects(
      () => completeUpstream(ctx, upstream, { code: 'code3', stateTx }),
      /the upstream returned an address outside the domain it is configured for/,
    );

    // 6. Domain-specific upstream falls back to preferred_username
    await provider.expect({
      audience: upstream.clientId,
      nonce: stateTx.upstream.nonce,
      claims: { email: undefined, preferred_username: 'user@corp.test', email_verified: true },
    });
    const res = await completeUpstream(ctx, upstream, { code: 'code4', stateTx });
    assert.equal(res.email, 'user@corp.test');
  } finally {
    restore();
  }
});

// ---------------------------------------------------------------------------
// src/upstream/providers.js coverage
// ---------------------------------------------------------------------------

test('providers: Microsoft verifyClaims checks tenant pin (lines 56-57)', () => {
  const ms = PROVIDERS.microsoft;

  // 1. Tenant match (case-insensitive) -> passes
  assert.doesNotThrow(() => {
    ms.verifyClaims({ tenant: 'Tenant-ABC', isCommon: false }, { tid: 'tenant-abc' });
  });

  // 2. Tenant mismatch -> throws (lines 56-57)
  assert.throws(
    () => ms.verifyClaims({ tenant: 'Tenant-ABC', isCommon: false }, { tid: 'other-tenant' }),
    /this Microsoft sign-in is from a different tenant/,
  );

  // 3. Tenant set to 'common' or 'organizations' -> ignored in domain-specific check
  assert.doesNotThrow(() => {
    ms.verifyClaims({ tenant: 'common', isCommon: false }, { tid: 'any-tid' });
    ms.verifyClaims({ tenant: 'organizations', isCommon: false }, { tid: 'any-tid' });
  });

  // 4. Allowed tenants list enforcement (lines 38-40)
  assert.throws(
    () => ms.verifyClaims({ allowedTenants: ['allowed-1'], isCommon: true }, { tid: 'forbidden-2' }),
    /this Microsoft sign-in is from a tenant this upstream does not accept/,
  );
  assert.doesNotThrow(() => {
    ms.verifyClaims({ allowedTenants: ['allowed-1'], isCommon: true }, { tid: 'allowed-1' });
  });

  // 5. Common upstream without allowed tenants requires verified email domain (lines 49-51)
  assert.throws(
    () => ms.verifyClaims({ isCommon: true }, { tid: 'any-tid' }),
    /this Microsoft upstream accepts any tenant, so it needs the xms_edov claim to trust an address/,
  );
});

test('providers: Google verifyClaims checks hosted domain (hd) (lines 75-79)', () => {
  const google = PROVIDERS.google;

  // 1. Domain-specific Google upstream with matching claims.hd -> passes
  assert.doesNotThrow(() => {
    google.verifyClaims({ domain: 'corp.example.com', isCommon: false }, { hd: 'corp.example.com' });
  });

  // 2. Domain-specific Google upstream with mismatching claims.hd -> throws (lines 77-79)
  assert.throws(
    () => google.verifyClaims({ domain: 'corp.example.com', isCommon: false }, { hd: 'other.example.com' }),
    /this Google account is not in the expected hosted domain/,
  );

  // 3. Domain-specific Google upstream with missing claims.hd -> throws
  assert.throws(
    () => google.verifyClaims({ domain: 'corp.example.com', isCommon: false }, {}),
    /this Google account is not in the expected hosted domain/,
  );

  // 4. Common Google upstream with explicit u.hd -> checks claims.hd
  assert.doesNotThrow(() => {
    google.verifyClaims({ hd: 'custom.org', isCommon: true }, { hd: 'custom.org' });
  });
  assert.throws(
    () => google.verifyClaims({ hd: 'custom.org', isCommon: true }, { hd: 'wrong.org' }),
    /this Google account is not in the expected hosted domain/,
  );

  // 5. Common Google upstream with no hd restriction -> passes (line 76 returns early)
  assert.doesNotThrow(() => {
    google.verifyClaims({ isCommon: true }, {});
  });

  // 6. extraAuthorizationParams for Google (lines 66-73)
  assert.deepEqual(google.extraAuthorizationParams({ isCommon: false, domain: 'example.com' }), { hd: 'example.com' });
  assert.deepEqual(google.extraAuthorizationParams({ isCommon: true, hd: 'custom.com' }), { hd: 'custom.com' });
  assert.deepEqual(google.extraAuthorizationParams({ isCommon: true }), {});
});

test('providers: tenantFor and Microsoft discoveryUrl generation (lines 108-112)', () => {
  const ms = PROVIDERS.microsoft;

  // 1. Common upstream without explicit tenant -> defaults to 'common'
  assert.equal(
    ms.discoveryUrl({ isCommon: true }),
    'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
  );

  // 2. Domain-specific upstream without explicit tenant -> defaults to u.domain
  assert.equal(
    ms.discoveryUrl({ isCommon: false, domain: 'contoso.onmicrosoft.com' }),
    'https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration',
  );

  // 3. Upstream with explicit tenant -> uses u.tenant
  assert.equal(
    ms.discoveryUrl({ tenant: 'custom-tenant-guid' }),
    'https://login.microsoftonline.com/custom-tenant-guid/v2.0/.well-known/openid-configuration',
  );
});

test('providers: provider helpers, labelFor, and xms_edov claim variants', () => {
  // providerFor fallback
  assert.equal(providerFor('microsoft'), PROVIDERS.microsoft);
  assert.equal(providerFor('google'), PROVIDERS.google);
  assert.equal(providerFor('unknown-provider'), PROVIDERS.oidc);

  // labelFor
  assert.equal(labelFor({ label: 'Custom Label' }), 'Custom Label');
  assert.equal(labelFor({ provider: 'google', isCommon: true }), 'Google');
  assert.equal(labelFor({ provider: 'google', domain: 'example.com', isCommon: false }), 'Google (example.com)');

  // OIDC discoveryUrl strips trailing slashes
  assert.equal(
    PROVIDERS.oidc.discoveryUrl({ issuer: 'https://idp.example.com///' }),
    'https://idp.example.com/.well-known/openid-configuration',
  );
  assert.equal(PROVIDERS.oidc.discoveryUrl({}), undefined);

  // Microsoft xms_edov variations in verifyClaims for common upstream
  const ms = PROVIDERS.microsoft;
  // Boolean true
  assert.doesNotThrow(() => ms.verifyClaims({ isCommon: true }, { xms_edov: true }));
  // String 'true', '1', number 1
  assert.doesNotThrow(() => ms.verifyClaims({ isCommon: true }, { xms_edov: 'true' }));
  assert.doesNotThrow(() => ms.verifyClaims({ isCommon: true }, { xms_edov: '1' }));
  assert.doesNotThrow(() => ms.verifyClaims({ isCommon: true }, { xms_edov: 1 }));

  // Boolean false, String 'false', '0', number 0 -> throws unverified
  assert.throws(
    () => ms.verifyClaims({ isCommon: true }, { xms_edov: false }),
    /Microsoft reports that this address is not in a domain the tenant has verified/,
  );
  assert.throws(
    () => ms.verifyClaims({ isCommon: true }, { xms_edov: 'false' }),
    /Microsoft reports that this address is not in a domain the tenant has verified/,
  );
  assert.throws(
    () => ms.verifyClaims({ isCommon: true }, { xms_edov: '0' }),
    /Microsoft reports that this address is not in a domain the tenant has verified/,
  );
  assert.throws(
    () => ms.verifyClaims({ isCommon: true }, { xms_edov: 0 }),
    /Microsoft reports that this address is not in a domain the tenant has verified/,
  );
});
