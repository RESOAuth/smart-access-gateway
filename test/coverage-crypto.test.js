import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createApp } from '../src/index.js';
import { supportsAlg, filterSupported, resetProbeCache } from '../src/crypto/capabilities.js';
import {
  webCryptoImportParams,
  webCryptoSignParams,
  importPrivateJwk,
  importPublicJwk,
  publicPartOf,
  validateClaims,
  derToRawEcdsa,
  pemToDer,
  pemPrivateToJwk,
  fetchJwks,
  selectJwk,
  clearJwksCache,
} from '../src/crypto/jose.js';
import {
  seal,
  unseal,
  derive,
  SealError,
} from '../src/crypto/secrets.js';
import { signRequest } from '../src/crypto/sigv4.js';
import { createKmsSigner } from '../src/keys/awskms.js';
import { createHsmSigner } from '../src/keys/cfhsm.js';
import { generateSigningKey } from '../src/keys/generate.js';
import { createSigner, signerKid } from '../src/keys/index.js';
import { createLocalSigner } from '../src/keys/local.js';
import { createPeerJwks } from '../src/keys/peers.js';
import { createSignerSet } from '../src/keys/registry.js';
import {
  concat,
  utf8,
  b64u,
  b64,
} from '../src/util/bytes.js';
import {
  OAuthError,
  UserFacingError,
  invalidRequest,
  invalidClient,
  invalidGrant,
  serverError,
  accessDenied,
  loginRequired,
  interactionRequired,
  unmetAcr,
} from '../src/util/errors.js';
import {
  parseCookies,
  readTextLimited,
  readForm,
  safeHttpUrl,
  BodyTooLargeError,
} from '../src/util/http.js';
import { isPublicIpv6, isPublicIp, isLoopbackIp } from '../src/util/ip.js';

// ---------------------------------------------------------------------------
// src/index.js
// ---------------------------------------------------------------------------

test('createApp binds environment and routes requests', async () => {
  const env = { SAG_ISSUER: 'http://localhost:8787', SAG_SECRET: 's'.repeat(32) };
  const app = createApp(env);
  const res = await app(new Request('http://localhost:8787/alive'));
  assert.equal(res.status, 200);
});

// ---------------------------------------------------------------------------
// src/crypto/capabilities.js
// ---------------------------------------------------------------------------

test('supportsAlg tests RSA branch and failure handling', async () => {
  resetProbeCache();
  const rs256Supported = await supportsAlg('RS256');
  assert.equal(typeof rs256Supported, 'boolean');

  // Probe caching
  const cached = await supportsAlg('RS256');
  assert.equal(cached, rs256Supported);

  // Unknown algorithm returns false early
  assert.equal(await supportsAlg('NON_EXISTENT_ALG'), false);

  // Failure in subtle.generateKey is caught and returns false
  resetProbeCache();
  const realGenerateKey = crypto.subtle.generateKey;
  try {
    crypto.subtle.generateKey = async () => {
      throw new Error('simulated failure');
    };
    assert.equal(await supportsAlg('ES256'), false);
  } finally {
    crypto.subtle.generateKey = realGenerateKey;
    resetProbeCache();
  }
});

test('filterSupported filters down to supported algorithms', async () => {
  resetProbeCache();
  const filtered = await filterSupported(['ES256', 'RS256', 'NOT_AN_ALG']);
  assert.ok(filtered.includes('ES256'));
  assert.ok(!filtered.includes('NOT_AN_ALG'));
});

// ---------------------------------------------------------------------------
// src/crypto/jose.js
// ---------------------------------------------------------------------------

test('webCryptoImportParams handles HMAC and RSA parameters', () => {
  assert.deepEqual(webCryptoImportParams('HS256'), { name: 'HMAC', hash: 'SHA-256' });
  assert.deepEqual(webCryptoImportParams('RS256'), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
  assert.deepEqual(webCryptoImportParams('PS256'), { name: 'RSA-PSS', hash: 'SHA-256' });
  assert.deepEqual(webCryptoSignParams('PS256'), { name: 'RSA-PSS', saltLength: 32 });
  assert.deepEqual(webCryptoSignParams('RS256'), 'RSASSA-PKCS1-v1_5');
});

test('assertKeyStrength requires RSA key for RSA algorithms', async () => {
  await assert.rejects(
    () => importPrivateJwk({ kty: 'EC', crv: 'P-256' }, 'RS256'),
    /RS256 requires an RSA key/,
  );
  await assert.rejects(
    () => importPublicJwk({ kty: 'EC', crv: 'P-256' }, 'RS256'),
    /RS256 requires an RSA key/,
  );
});

test('publicPartOf requires alg on AKP keys', () => {
  assert.throws(
    () => publicPartOf({ kty: 'AKP', pub: 'pub-bytes' }),
    /an AKP JWK must carry an alg member/,
  );
});

test('validateClaims validates max_age', () => {
  const now = Math.floor(Date.now() / 1000);
  // Missing auth_time when maxAge is requested
  assert.throws(
    () => validateClaims({ iss: 'iss', exp: now + 300 }, { maxAge: 60 }),
    /auth_time required when max_age is requested/,
  );
  // auth_time too old
  assert.throws(
    () => validateClaims({ iss: 'iss', exp: now + 300, auth_time: now - 500 }, { maxAge: 60 }),
    /authentication too old for max_age/,
  );
  // Valid auth_time
  const validated = validateClaims({ iss: 'iss', exp: now + 300, auth_time: now - 30 }, { maxAge: 60 });
  assert.equal(validated.auth_time, now - 30);
});

test('derToRawEcdsa handles multi-byte DER sequence lengths', () => {
  const r = new Uint8Array(32).fill(1);
  const s = new Uint8Array(32).fill(2);
  // 0x81 indicates 1 byte length (0x44 = 68 bytes follows)
  const der = new Uint8Array([0x30, 0x81, 0x44, 0x02, 0x20, ...r, 0x02, 0x20, ...s]);
  const raw = derToRawEcdsa(der, 'P-256');
  assert.equal(raw.length, 64);
  assert.deepEqual(raw.subarray(0, 32), r);
  assert.deepEqual(raw.subarray(32), s);
});

test('pemToDer rejects empty PEM bodies and decodes valid bodies', () => {
  assert.throws(() => pemToDer(''), /no PEM body found/);
  assert.throws(() => pemToDer('-----BEGIN KEY-----\n-----END KEY-----'), /no PEM body found/);
  const decoded = pemToDer('-----BEGIN KEY-----\nAQID\n-----END KEY-----');
  assert.deepEqual(decoded, new Uint8Array([1, 2, 3]));
});

test('pemPrivateToJwk imports a PKCS#8 PEM into a JWK', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const pem = `-----BEGIN PRIVATE KEY-----\n${b64(pkcs8)}\n-----END PRIVATE KEY-----`;
  const jwk = await pemPrivateToJwk(pem, 'ES256');
  assert.equal(jwk.kty, 'EC');
  assert.equal(jwk.alg, 'ES256');
  assert.ok(jwk.d);
});

test('fetchJwks validates URLs and manages cache expiry and eviction', async () => {
  clearJwksCache();
  await assert.rejects(() => fetchJwks('not-a-valid-url'), /JWKS URI is not an absolute URL/);

  const realFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ keys: [{ kty: 'EC', crv: 'P-256', kid: 'k1', x: 'x', y: 'y' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });

    // Populate an expired entry and a fresh entry to exercise cleanup on line 249-250
    await fetchJwks('https://example.com/expired.json', { ttlSeconds: -10 });
    await fetchJwks('https://example.com/fresh.json', { ttlSeconds: 300 });

    // Fill the cache up to and beyond MAX_JWKS_CACHE_ENTRIES to exercise eviction on line 253-255
    for (let i = 0; i < 505; i++) {
      await fetchJwks(`https://example.com/jwks-${i}.json`, { ttlSeconds: 300 });
    }
  } finally {
    globalThis.fetch = realFetch;
    clearJwksCache();
  }
});

test('selectJwk falls back to single candidate or errors on ambiguous/empty set', () => {
  const k1 = { kty: 'EC', crv: 'P-256', kid: 'k1', alg: 'ES256' };
  const k2 = { kty: 'EC', crv: 'P-256', kid: 'k2', alg: 'ES256' };

  // Single candidate without kid in header
  assert.equal(selectJwk({ keys: [k1] }, { alg: 'ES256' }), k1);

  // Empty matching set
  assert.throws(() => selectJwk({ keys: [] }, { alg: 'ES256' }), /no matching key in JWKS/);

  // Ambiguous matching set without kid
  assert.throws(() => selectJwk({ keys: [k1, k2] }, { alg: 'ES256' }), /no matching key in JWKS/);
});

// ---------------------------------------------------------------------------
// src/crypto/secrets.js
// ---------------------------------------------------------------------------

test('unseal handles malformed base64, malformed payload, and maxAgeSeconds', async () => {
  const secret = 'test-secret-1234567890123456789012';
  const purpose = 'test';

  // Malformed base64url IV/CT
  await assert.rejects(
    () => unseal(secret, purpose, 'k1.test.bad!iv.bad!ct'),
    SealError,
  );

  // Decrypted plaintext is malformed JSON
  const rawKey = await derive(secret, 'aead/' + purpose, 32);
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const iv = new Uint8Array(12);
  const aad = utf8('k1.' + purpose);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      key,
      utf8('not json {'),
    ),
  );
  const malformedJsonToken = `k1.${purpose}.${b64u(iv)}.${b64u(ct)}`;
  await assert.rejects(
    () => unseal(secret, purpose, malformedJsonToken),
    (err) => err instanceof SealError && err.message === 'malformed payload',
  );

  // Expired by maxAgeSeconds
  const now = Math.floor(Date.now() / 1000);
  const oldPayload = { msg: 'hi', iat: now - 300 };
  const oldToken = await seal(secret, purpose, oldPayload);
  await assert.rejects(
    () => unseal(secret, purpose, oldToken, { maxAgeSeconds: 60 }),
    (err) => err instanceof SealError && err.message === 'token too old',
  );
});

// ---------------------------------------------------------------------------
// src/crypto/sigv4.js
// ---------------------------------------------------------------------------

test('signRequest encodes special RFC3986 characters and checks credentials', async () => {
  // Query parameters with special characters exercising encodeRfc3986 non-unreserved branch
  const signed = await signRequest({
    method: 'GET',
    url: 'https://kms.us-east-1.amazonaws.com/?special=%20%21%40%23%24%25%5E%26%2A%28%29%2B%3D',
    service: 'kms',
    region: 'us-east-1',
    credentials: { accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'secret' },
  });
  assert.ok(signed.authorization);

  // Missing credentials
  await assert.rejects(
    () => signRequest({
      method: 'GET',
      url: 'https://kms.us-east-1.amazonaws.com/',
      service: 'kms',
      region: 'us-east-1',
      credentials: {},
    }),
    /AWS credentials are required to sign a kms request/,
  );
});

// ---------------------------------------------------------------------------
// src/keys/awskms.js
// ---------------------------------------------------------------------------

test('createKmsSigner kid getter and keyId method', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));

  const realFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ PublicKey: b64(spki) }), {
        status: 200,
        headers: { 'content-type': 'application/x-amz-json-1.1' },
      });

    const signer = await createKmsSigner({
      keyId: 'alias/test-key',
      region: 'us-east-1',
      credentials: { accessKeyId: 'AKIA', secretAccessKey: 'sec' },
      alg: 'ES256',
    });

    assert.equal(signer.kid, undefined);
    const resolvedKid = await signer.keyId();
    assert.ok(resolvedKid);
    assert.equal(signer.kid, resolvedKid);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ---------------------------------------------------------------------------
// src/keys/cfhsm.js
// ---------------------------------------------------------------------------

test('createHsmSigner error handling and keyId method', async () => {
  // Binding returning 500 error response
  const failingBinding = {
    fetch: async () => new Response('Internal HSM Error', { status: 500 }),
  };
  const failingSigner = await createHsmSigner({
    binding: failingBinding,
    sharedSecret: 'secret',
  });
  await assert.rejects(
    () => failingSigner.publicJwks(),
    /HSM \/jwks failed with HTTP 500 Internal HSM Error/,
  );

  // keyId() resolution when kid is not yet known
  const workingBinding = {
    fetch: async () =>
      new Response(
        JSON.stringify({ keys: [{ kty: 'EC', crv: 'P-256', kid: 'hsm-test-kid-1' }] }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
  };
  const workingSigner = await createHsmSigner({
    binding: workingBinding,
    sharedSecret: 'secret',
  });
  const resolvedKid = await workingSigner.keyId();
  assert.equal(resolvedKid, 'hsm-test-kid-1');
  assert.equal(workingSigner.kid, 'hsm-test-kid-1');
});

// ---------------------------------------------------------------------------
// src/keys/generate.js
// ---------------------------------------------------------------------------

test('generateSigningKey validates algorithms and handles RSA', async () => {
  await assert.rejects(
    () => generateSigningKey('HS256'),
    /HS256 cannot sign id_tokens/,
  );

  await assert.rejects(
    () => generateSigningKey('UNKNOWN_UNSUPPORTED_ALG'),
    /UNKNOWN_UNSUPPORTED_ALG is not available on this runtime/,
  );

  const rsa = await generateSigningKey('RS256');
  assert.equal(rsa.alg, 'RS256');
  assert.equal(rsa.publicJwk.kty, 'RSA');
});

// ---------------------------------------------------------------------------
// src/keys/index.js
// ---------------------------------------------------------------------------

test('createSigner rejects unknown backend and signerKid resolves keyId', async () => {
  await assert.rejects(
    () => createSigner({ signing: { backend: 'unknown-backend' } }),
    /unknown signing backend: unknown-backend/,
  );

  // signer with keyId method
  assert.equal(await signerKid({ keyId: async () => 'resolved-kid-1' }), 'resolved-kid-1');

  // signer with publicJwks without kid property on the key
  const thumb = await signerKid({
    publicJwks: async () => ({ keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }] }),
  });
  assert.ok(typeof thumb === 'string' && thumb.length > 0);

  // signer with empty publicJwks keys
  assert.equal(await signerKid({ publicJwks: async () => ({ keys: [] }) }), undefined);
});

// ---------------------------------------------------------------------------
// src/keys/local.js
// ---------------------------------------------------------------------------

test('createLocalSigner validates alg, generates RSA, handles errors, and exports keys', async () => {
  await assert.rejects(
    () => createLocalSigner({ alg: 'HS256' }),
    /HS256 cannot sign id_tokens for public clients/,
  );

  const rsaSigner = await createLocalSigner({ alg: 'RS256' });
  assert.equal(rsaSigner.alg, 'RS256');

  // Error during key generation
  const realGenerateKey = crypto.subtle.generateKey;
  try {
    crypto.subtle.generateKey = async () => {
      throw new Error('keygen failed');
    };
    await assert.rejects(
      () => createLocalSigner({ alg: 'ES256' }),
      /this runtime cannot generate a ES256 key: keygen failed/,
    );
  } finally {
    crypto.subtle.generateKey = realGenerateKey;
  }

  // publicJwk and exportPrivateJwk
  const signer = await createLocalSigner({ alg: 'ES256' });
  const pub = await signer.publicJwk();
  assert.equal(pub.kty, 'EC');
  const priv = signer.exportPrivateJwk();
  assert.equal(priv.kty, 'EC');
  assert.ok(priv.d);
});

// ---------------------------------------------------------------------------
// src/keys/peers.js
// ---------------------------------------------------------------------------

test('createPeerJwks handles invalid json, cache exceptions, logging, and describe', async () => {
  const url = 'https://peer.example.test/.well-known/jwks.json';
  const config = {
    peerJwks: {
      urls: [url],
      cacheTtlSeconds: 300,
      staleTtlSeconds: 1000,
      retryAfterSeconds: 30,
      timeoutMs: 1000,
      maxDocumentBytes: 64 * 1024,
      cacheBackend: 'memory',
    },
  };

  const realFetch = globalThis.fetch;
  try {
    // 1. Peer returns invalid JSON
    globalThis.fetch = async () =>
      new Response('invalid json {', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });

    const peerJwks = createPeerJwks(config);
    const res = await peerJwks.collect();
    assert.deepEqual(res.keys, []);
    assert.equal(res.incomplete, true);

    // 2. describe() with cached entry
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ keys: [{ kty: 'EC', crv: 'P-256', kid: 'peer-k1', x: 'x', y: 'y' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });

    const peerJwks2 = createPeerJwks({
      peerJwks: { ...config.peerJwks, retryAfterSeconds: 0 },
    });
    await peerJwks2.collect();
    const desc = await peerJwks2.describe();
    assert.equal(desc.length, 1);
    assert.equal(desc[0].key_count, 1);
    assert.equal(desc[0].within_cache_ttl, true);
    assert.equal(desc[0].within_grace_period, true);

    assert.equal(await peerJwks2.peek('https://nonexistent.test'), undefined);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('peer jwks logs cache read and write warnings', async () => {
  const url = 'https://peer-log-test.example.test/.well-known/jwks.json';
  const warnings = [];
  const log = {
    warn: (msg, meta) => warnings.push({ msg, meta }),
  };

  // KV cache throwing read and write
  const badKv = {
    get: async () => {
      throw new Error('kv read err');
    },
    put: async () => {
      throw new Error('kv write err');
    },
  };

  const config = {
    peerJwks: {
      urls: [url],
      cacheTtlSeconds: 300,
      staleTtlSeconds: 1000,
      retryAfterSeconds: 0,
      timeoutMs: 1000,
      maxDocumentBytes: 64 * 1024,
      cacheBackend: 'cf-kv',
      cacheKvBindingName: 'KV',
    },
  };

  const realFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ keys: [{ kty: 'EC', crv: 'P-256', kid: 'k1', x: 'x', y: 'y' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });

    const peers = createPeerJwks(config, { KV: badKv });
    // peek() catches and returns undefined (line 267-268)
    assert.equal(await peers.peek(url), undefined);

    // collect() encounters cache read error (line 308-309) and cache write error (line 329-330)
    const result = await peers.collect({ log });
    assert.equal(result.keys.length, 1);
    assert.ok(warnings.some((w) => w.msg === 'peer jwks cache read failed'));
    assert.ok(warnings.some((w) => w.msg === 'peer jwks cache write failed'));
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ---------------------------------------------------------------------------
// src/keys/registry.js
// ---------------------------------------------------------------------------

test('createSignerSet skips unsupported local algs, fails if empty, and exposes kid()', async () => {
  const config = {
    signing: {
      backend: 'local',
      alg: 'ES256',
      additionalAlgs: ['UNKNOWN_ALG_NAME'],
      keysByAlg: {},
    },
  };
  const set = await createSignerSet(config);
  assert.ok(set.skipped.some((s) => s.alg === 'UNKNOWN_ALG_NAME'));

  const kid = await set.kid('ES256');
  assert.ok(kid);

  // Fails when no usable key can be initialized
  const emptyConfig = {
    signing: {
      backend: 'local',
      alg: 'UNKNOWN_ALG_NAME',
      additionalAlgs: [],
      keysByAlg: {},
    },
  };
  await assert.rejects(
    () => createSignerSet(emptyConfig),
    /no usable signing key: could not initialise UNKNOWN_ALG_NAME/,
  );
});

// ---------------------------------------------------------------------------
// src/util/bytes.js
// ---------------------------------------------------------------------------

test('concat joins byte arrays', () => {
  const a = new Uint8Array([1, 2]);
  const b = new Uint8Array([3, 4, 5]);
  const c = new Uint8Array([6]);
  assert.deepEqual(concat(a, b, c), new Uint8Array([1, 2, 3, 4, 5, 6]));
  assert.deepEqual(concat(), new Uint8Array([]));
});

// ---------------------------------------------------------------------------
// src/util/errors.js
// ---------------------------------------------------------------------------

test('UserFacingError and OAuthError helpers', () => {
  const userErr = new UserFacingError('Title', 'Detail message', 403);
  assert.equal(userErr.name, 'UserFacingError');
  assert.equal(userErr.title, 'Title');
  assert.equal(userErr.detail, 'Detail message');
  assert.equal(userErr.status, 403);

  const oauthErr = new OAuthError('invalid_request', 'Description', { uri: 'https://example.com/err' });
  assert.deepEqual(oauthErr.toJSON(), {
    error: 'invalid_request',
    error_description: 'Description',
    error_uri: 'https://example.com/err',
  });

  assert.equal(invalidRequest('d').code, 'invalid_request');
  assert.equal(invalidClient('d').status, 401);
  assert.equal(invalidGrant('d').code, 'invalid_grant');
  assert.equal(serverError('d').status, 500);
  assert.equal(accessDenied('d').code, 'access_denied');
  assert.equal(loginRequired('d').code, 'login_required');
  assert.equal(interactionRequired('d').code, 'interaction_required');
  assert.equal(unmetAcr('d').code, 'unmet_authentication_requirements');
});

// ---------------------------------------------------------------------------
// src/util/http.js
// ---------------------------------------------------------------------------

test('parseCookies handles invalid percent escapes gracefully', () => {
  const cookies = parseCookies(new Request('http://localhost', {
    headers: { cookie: 'malformed=%E0%A4%A; valid=hello%20world' },
  }));
  assert.equal(cookies.get('malformed'), '%E0%A4%A');
  assert.equal(cookies.get('valid'), 'hello world');
});

test('readTextLimited checks declared content-length header', async () => {
  const res = new Response('small', {
    headers: { 'content-length': '1000' },
  });
  await assert.rejects(
    () => readTextLimited(res, 50),
    BodyTooLargeError,
  );
});

test('readForm validates content-type and body size limit', async () => {
  // Wrong content-type
  const jsonReq = new Request('http://localhost', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ a: 1 }),
  });
  await assert.rejects(
    () => readForm(jsonReq),
    /Request body must be application\/x-www-form-urlencoded/,
  );

  // Body too large
  const largeReq = new Request('http://localhost', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'content-length': '1000000',
    },
    body: 'a=1',
  });
  await assert.rejects(
    () => readForm(largeReq),
    /Request body too large/,
  );
});

test('safeHttpUrl returns undefined on unparseable URLs', () => {
  assert.equal(safeHttpUrl(':::not-a-valid-url:::'), undefined);
});

// ---------------------------------------------------------------------------
// src/util/ip.js
// ---------------------------------------------------------------------------

test('ip classification for IPv4-mapped IPv6, loopback and transitions', () => {
  // IPv4-mapped IPv6 addresses
  assert.equal(isPublicIp('::ffff:192.168.1.1'), false);
  assert.equal(isPublicIp('::ffff:8.8.8.8'), true);
  assert.equal(isPublicIpv6('::ffff:8.8.8.8'), true);
  assert.equal(isPublicIpv6('::ffff:10.0.0.1'), false);
  assert.equal(isPublicIp('::ffff:300.300.300.300'), false);

  // Loopback checks
  assert.equal(isLoopbackIp('::1'), true);
  assert.equal(isLoopbackIp('[::1]'), true);
  assert.equal(isLoopbackIp('127.0.0.1'), true);
  assert.equal(isLoopbackIp('127.1.2.3'), true);
  assert.equal(isLoopbackIp('8.8.8.8'), false);
  assert.equal(isLoopbackIp('2001:4860:4860::8888'), false);

  // Transition mechanisms
  assert.equal(isPublicIp('2002:0a00:0001::'), false); // 6to4 10.0.0.1
  assert.equal(isPublicIp('2002:0808:0808::'), true);  // 6to4 8.8.8.8
  assert.equal(isPublicIp('2001:0000:0000:0000:0000:0000:f7f7:f7f7'), true);  // Teredo 8.8.8.8
  assert.equal(isPublicIp('2001:0000:0000:0000:0000:0000:f5ff:feff'), false); // Teredo 10.0.1.0
});
