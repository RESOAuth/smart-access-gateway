// Post-quantum signing, end to end.
//
// docs/post-quantum.md claims a relying party can migrate to a lattice
// signature one at a time, with no flag day. These tests hold that claim to
// account: they run complete sign-ins and verify the resulting id_tokens the
// way a relying party would, so "algorithm agile" means something testable
// rather than aspirational.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, signInWithOtp, redeem } from './harness.js';
import { supportsAlg, cryptoReport, resetProbeCache } from '../src/crypto/capabilities.js';
import { verifyCompact, decodeJwt, ALGS, POST_QUANTUM_ALGS, isPostQuantum } from '../src/crypto/jose.js';
import { createSignerSet } from '../src/keys/registry.js';
import { loadConfig } from '../src/config.js';

const EMAIL = 'person@example.org';

/** Skip a test cleanly on a runtime without lattice signatures. */
async function requirePq(t, alg = 'ML-DSA-44') {
  if (await supportsAlg(alg)) return true;
  t.skip('this runtime has no ' + alg + ' support');
  return false;
}

/** Fetch the JWKS and verify an id_token exactly as a relying party would. */
async function verifyAsRelyingParty(sag, idToken) {
  const { body: jwks } = await sag.json('/jwks.json');
  const { header } = decodeJwt(idToken);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  assert.ok(jwk, 'the kid in the header must be published: ' + header.kid);
  return { claims: await verifyCompact(idToken, jwk), header, jwk };
}

test('every declared lattice parameter set can be probed', async () => {
  resetProbeCache();
  const report = await cryptoReport();
  assert.ok(report.supported.includes('ES256'), 'a classical baseline must always work');
  // Whether they are available is the runtime's business; that the probe
  // answers without throwing is ours.
  for (const alg of POST_QUANTUM_ALGS) {
    assert.ok(report.supported.includes(alg) || report.unsupported.includes(alg), alg + ' was not reported either way');
  }
});

test('an id_token can be signed with ML-DSA-44 and verified from the JWKS', async (t) => {
  if (!(await requirePq(t))) return;

  const sag = createInstance({ SIGNING_ALG: 'ML-DSA-44' });
  const flow = await signInWithOtp(sag, { email: EMAIL });
  const { res, body } = await redeem(sag, flow);
  assert.equal(res.status, 200, JSON.stringify(body));

  const { claims, header, jwk } = await verifyAsRelyingParty(sag, body.id_token);
  assert.equal(header.alg, 'ML-DSA-44');
  assert.equal(claims.email, EMAIL);
  assert.equal(claims.nonce, flow.nonce);

  // A lattice key is published as a JOSE AKP key, where alg is required
  // because kty alone does not pin the parameter set.
  assert.equal(jwk.kty, 'AKP');
  assert.equal(jwk.alg, 'ML-DSA-44');
  assert.ok(jwk.pub, 'the raw public key bytes must be published');
  assert.equal(jwk.priv, undefined, 'and the private half must not be');
});

test('the published key and signature are the sizes FIPS 204 specifies', async (t) => {
  if (!(await requirePq(t))) return;

  const sag = createInstance({ SIGNING_ALG: 'ML-DSA-44' });
  const flow = await signInWithOtp(sag, { email: EMAIL });
  const { body } = await redeem(sag, flow);
  const { signature } = decodeJwt(body.id_token);
  const { body: jwks } = await sag.json('/jwks.json');

  const spec = ALGS['ML-DSA-44'];
  assert.equal(signature.length, spec.signatureBytes, 'signature should be ' + spec.signatureBytes + ' bytes');

  // base64url of n bytes is ceil(n * 4 / 3) characters without padding.
  const pubBytes = Math.floor((jwks.keys[0].pub.length * 3) / 4);
  assert.equal(pubBytes, spec.publicKeyBytes, 'public key should be ' + spec.publicKeyBytes + ' bytes');

  // Worth knowing rather than discovering in production: a lattice id_token is
  // several times larger, which matters to anybody putting one in a header.
  assert.ok(body.id_token.length > 3000, 'a lattice id_token is large: ' + body.id_token.length);
});

test('a classical and a lattice key are published together, classical primary', async (t) => {
  if (!(await requirePq(t))) return;

  const sag = createInstance({ SIGNING_ALG: 'ES256', SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44' });

  const { body: discovery } = await sag.json('/.well-known/openid-configuration');
  assert.deepEqual(discovery.id_token_signing_alg_values_supported, ['ES256', 'ML-DSA-44']);
  assert.equal(discovery['urn:sag:post_quantum_signing_supported'], true);
  assert.deepEqual(discovery['urn:sag:post_quantum_algs'], ['ML-DSA-44']);

  const { body: jwks } = await sag.json('/jwks.json');
  assert.equal(jwks.keys.length, 2);
  assert.equal(jwks.keys[0].alg, 'ES256', 'the primary must come first so a naive client picks it');
});

test('a relying party opts into lattice signatures per request, one at a time', async (t) => {
  if (!(await requirePq(t))) return;

  // This is the migration story: two relying parties on the same deployment,
  // getting different algorithms, with no coordinated change.
  const sag = createInstance({
    SIGNING_ALG: 'ES256',
    SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44',
    CLIENT_LEGACY_ID: 'legacy-app',
    CLIENT_LEGACY_REDIRECT_URIS: 'https://legacy.test/cb',
    CLIENT_MODERN_ID: 'modern-app',
    CLIENT_MODERN_REDIRECT_URIS: 'https://modern.test/cb',
    // A client record can pin the algorithm, so the relying party does not
    // have to change its request at all.
    CLIENT_MODERN_ID_TOKEN_SIGNED_RESPONSE_ALG: 'ML-DSA-44',
  });

  const legacy = await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'legacy-app', redirectUri: 'https://legacy.test/cb' },
  });
  const legacyTokens = await redeem(sag, {
    ...legacy,
    clientId: 'legacy-app',
    redirectUri: 'https://legacy.test/cb',
  });
  assert.equal(legacyTokens.res.status, 200, JSON.stringify(legacyTokens.body));
  assert.equal(decodeJwt(legacyTokens.body.id_token).header.alg, 'ES256');

  sag.clearCookies();
  const modern = await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { clientId: 'modern-app', redirectUri: 'https://modern.test/cb' },
  });
  const modernTokens = await redeem(sag, {
    ...modern,
    clientId: 'modern-app',
    redirectUri: 'https://modern.test/cb',
  });
  assert.equal(modernTokens.res.status, 200, JSON.stringify(modernTokens.body));
  assert.equal(decodeJwt(modernTokens.body.id_token).header.alg, 'ML-DSA-44');

  // Both verify against the one published JWKS.
  await verifyAsRelyingParty(sag, legacyTokens.body.id_token);
  await verifyAsRelyingParty(sag, modernTokens.body.id_token);
});

test('a relying party can also ask for the algorithm in the request', async (t) => {
  if (!(await requirePq(t))) return;

  const sag = createInstance({ SIGNING_ALG: 'ES256', SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44' });
  const flow = await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { id_token_signed_response_alg: 'ML-DSA-44' },
  });
  const { body } = await redeem(sag, flow);
  assert.equal(decodeJwt(body.id_token).header.alg, 'ML-DSA-44');
});

test('asking for an algorithm this deployment does not offer is a clear refusal', async () => {
  const sag = createInstance({ SIGNING_ALG: 'ES256' });
  const flow = await signInWithOtp(sag, {
    email: EMAIL,
    authorize: { id_token_signed_response_alg: 'ML-DSA-87' },
  });
  const { res, body } = await redeem(sag, flow);
  assert.equal(res.status, 400);
  assert.equal(body.error, 'invalid_request');
  // The message must say what is on offer, not just that the request failed.
  assert.match(body.error_description, /this deployment offers ES256/);
});

test('an unknown algorithm name is rejected at configuration time', () => {
  // Better than skipping it: a typo in SIGNING_ADDITIONAL_ALGS should be found
  // when the operator deploys, not silently ignored until somebody asks for it.
  assert.throws(
    () =>
      loadConfig({
        SAG_ISSUER: 'https://id.example.test',
        SAG_SECRET: 'x'.repeat(48),
        SIGNING_ALG: 'ES256',
        SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44,ML-DAS-44',
      }),
    /contains an unusable algorithm: "ML-DAS-44"/,
  );
});

test('an additional key that cannot be built is skipped, but a broken primary is fatal', async () => {
  // Adding a second key to a mixed fleet must not take down a node that cannot
  // use it, so an additional signer that fails to initialise is recorded and
  // stepped over. The primary is different: serving with no usable signing key
  // would mean issuing nothing, so that has to stop the deployment.
  const rubbish = JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'nope', y: 'nope', d: 'nope' });

  const tolerant = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'x'.repeat(48),
    SAG_DEV: 'true',
    SIGNING_ALG: 'ES256',
    SIGNING_ADDITIONAL_ALGS: 'ES384',
    SIGNING_PRIVATE_JWK_ES384: rubbish,
  });
  const set = await createSignerSet(tolerant, {});
  assert.equal(set.primaryAlg, 'ES256');
  assert.deepEqual(set.algs, ['ES256'], 'the broken one must not be published');
  assert.equal(set.skipped.length, 1);
  assert.equal(set.skipped[0].alg, 'ES384');
  assert.ok(set.skipped[0].reason, 'and the reason must be recorded, not swallowed');

  const fatal = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'x'.repeat(48),
    SAG_DEV: 'true',
    SIGNING_ALG: 'ES256',
    SIGNING_PRIVATE_JWK: rubbish,
  });
  await assert.rejects(() => createSignerSet(fatal, {}));
});

test('a configured additional key is used, not regenerated on each start', async (t) => {
  if (!(await requirePq(t))) return;

  // The bug this pins: if the additional signer is handed the primary's key
  // material it falls back to generating an ephemeral one, so the JWKS
  // advertises a post-quantum key whose kid changes on every restart and every
  // token signed with it stops verifying.
  const pair = await crypto.subtle.generateKey({ name: 'ML-DSA-44' }, true, ['sign', 'verify']);
  const jwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), alg: 'ML-DSA-44' };
  const env = {
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'x'.repeat(48),
    SAG_DEV: 'true',
    SIGNING_ALG: 'ES256',
    SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44',
    SIGNING_PRIVATE_JWK_ML_DSA_44: JSON.stringify(jwk),
  };

  const kidFor = async () => {
    const set = await createSignerSet(loadConfig(env), {});
    const keys = (await set.jwks()).keys;
    const lattice = keys.find((k) => k.alg === 'ML-DSA-44');
    assert.ok(lattice, 'the lattice key must be published');
    return lattice.kid;
  };

  const first = await kidFor();
  const second = await kidFor();
  assert.equal(first, second, 'the same configured key must come back, restart after restart');

  // And the primary must still be its own key, not the lattice one.
  const set = await createSignerSet(loadConfig(env), {});
  assert.equal(set.primaryAlg, 'ES256');
  const es256 = (await set.jwks()).keys.find((k) => k.alg === 'ES256');
  assert.notEqual(es256.kid, first);
});

test('a deployment can refuse to start without a post-quantum key', async () => {
  assert.throws(
    () =>
      loadConfig({
        SAG_ISSUER: 'https://id.example.test',
        SAG_SECRET: 'x'.repeat(48),
        SIGNING_ALG: 'ES256',
        REQUIRE_POST_QUANTUM_SIGNING: 'true',
      }),
    /names a post-quantum algorithm/,
  );

  // And it starts happily when one is configured.
  const ok = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'x'.repeat(48),
    SIGNING_ALG: 'ES256',
    SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44',
    REQUIRE_POST_QUANTUM_SIGNING: 'true',
    EMAIL_PROVIDER: 'mailchannels',
    EMAIL_FROM: 'a@b.test',
  });
  assert.equal(ok.signing.requirePostQuantum, true);
  assert.ok(ok.signing.additionalAlgs.some(isPostQuantum));
});

test('the older SIGNING_REQUIRE_POST_QUANTUM name still works', () => {
  assert.throws(
    () =>
      loadConfig({
        SAG_ISSUER: 'https://id.example.test',
        SAG_SECRET: 'x'.repeat(48),
        SIGNING_ALG: 'ES256',
        SIGNING_REQUIRE_POST_QUANTUM: 'true',
      }),
    /SIGNING_REQUIRE_POST_QUANTUM is set but neither/,
  );
});

test('the signer set reports what it skipped rather than failing silently', async (t) => {
  if (!(await requirePq(t, 'ML-DSA-87'))) return;

  const config = loadConfig({
    SAG_ISSUER: 'https://id.example.test',
    SAG_SECRET: 'x'.repeat(48),
    SAG_DEV: 'true',
    SIGNING_ALG: 'ES256',
    SIGNING_ADDITIONAL_ALGS: 'ML-DSA-44,ML-DSA-65,ML-DSA-87',
  });
  const set = await createSignerSet(config, {});

  assert.equal(set.primaryAlg, 'ES256');
  assert.equal(set.hasPostQuantum, true);
  assert.deepEqual(set.postQuantumAlgs, ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']);

  const described = set.describe();
  assert.equal(described.post_quantum_signatures, true);
  assert.ok(Array.isArray(described.skipped), 'whatever could not be built must be listed');

  // Every published key must be distinct and complete.
  const jwks = await set.jwks();
  assert.equal(jwks.keys.length, 4);
  assert.equal(new Set(jwks.keys.map((k) => k.kid)).size, 4, 'no duplicate kids');
  for (const key of jwks.keys) {
    assert.ok(key.alg, 'every key needs an alg, because AKP kty does not pin the parameter set');
    assert.equal(key.use, 'sig');
    assert.equal(key.d, undefined);
    assert.equal(key.priv, undefined);
  }
});

test('confidentiality does not depend on the signing algorithm at all', async (t) => {
  if (!(await requirePq(t))) return;

  // The design claim in docs/post-quantum.md is that sessions and state are
  // sealed with AES-256-GCM regardless, so switching the signature scheme
  // changes nothing about them. A session minted under one algorithm must
  // therefore still work when the deployment is signing with the other.
  const shared = { SAG_SECRET: 'shared-secret-'.repeat(4) };
  const classical = createInstance({ ...shared, SIGNING_ALG: 'ES256' });
  await signInWithOtp(classical, { email: EMAIL });
  const cookie = [...classical.cookies][0];

  const lattice = createInstance({ ...shared, SIGNING_ALG: 'ML-DSA-44' });
  lattice.cookies.set(cookie[0], cookie[1]);

  const flow = await signInWithOtp(lattice, {
    email: EMAIL,
    authorize: { prompt: 'login' },
  });
  const { res, body } = await redeem(lattice, flow);
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.equal(decodeJwt(body.id_token).header.alg, 'ML-DSA-44');
});
