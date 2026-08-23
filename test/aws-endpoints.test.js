// Pointing SAG's AWS backends somewhere that is not AWS.
//
// SAG signs its own requests to KMS, DynamoDB and S3 rather than carrying an
// SDK, so an endpoint override is only a base URL - which is what makes a local
// stack, an S3-compatible bucket, or DynamoDB Local possible at all. The
// variable names are the SDK's own, so an environment already set up for an
// emulator works unchanged.
//
// These tests are also the only place the KMS signing path is exercised end to
// end: a real ECDSA key, a DER encoded signature as KMS returns it, and the
// resulting id_token verified against the JWKS SAG publishes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto as crypto } from 'node:crypto';
import { loadConfig } from '../src/config.js';
import { createSigner } from '../src/keys/index.js';
import { createStateStore } from '../src/store/index.js';
import { createClientStore } from '../src/clients/store.js';

const awsEnv = { AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE', AWS_SECRET_ACCESS_KEY: 'secret' };
const DEV = 'http://localhost:8787';

/** Record every outbound call and answer it from a callback. */
function fetchStub(responder) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    calls.push({ url, init });
    return responder(url, init, calls.length);
  };
  return {
    calls,
    restore: () => {
      globalThis.fetch = real;
    },
  };
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

test('an endpoint override is read per service, with a global fallback', () => {
  const specific = loadConfig({
    SAG_ISSUER: DEV,
    AWS_ENDPOINT_URL: 'http://everything:4566',
    AWS_ENDPOINT_URL_KMS: 'http://just-kms:4566',
  });
  assert.equal(specific.signing.kmsEndpoint, 'http://just-kms:4566');
  assert.equal(specific.stateStore.endpoint, 'http://everything:4566');
  assert.equal(specific.clients.store.s3Endpoint, 'http://everything:4566');

  // Unset is unset: a deployment that says nothing must go to AWS itself.
  const none = loadConfig({ SAG_ISSUER: DEV });
  assert.equal(none.signing.kmsEndpoint, undefined);
  assert.equal(none.stateStore.endpoint, undefined);
  assert.equal(none.clients.store.s3Endpoint, undefined);
});

test('a trailing slash is trimmed, so a path is never doubled', () => {
  const config = loadConfig({ SAG_ISSUER: DEV, AWS_ENDPOINT_URL_S3: 'http://minio:9000///' });
  assert.equal(config.clients.store.s3Endpoint, 'http://minio:9000');
});

test('something that is not a URL is refused rather than requested', () => {
  assert.throws(
    () => loadConfig({ SAG_ISSUER: DEV, AWS_ENDPOINT_URL_KMS: 'http://[nonsense' }),
    /AWS_ENDPOINT_URL_KMS must be an absolute URL/,
  );
  // A bare host and port is the likely mistake, and the message says what is
  // missing rather than that it is unparseable, because it parses fine.
  assert.throws(
    () => loadConfig({ SAG_ISSUER: DEV, AWS_ENDPOINT_URL_KMS: 'localstack:4566' }),
    /AWS_ENDPOINT_URL_KMS must be an http or https URL/,
  );
  assert.throws(
    () => loadConfig({ SAG_ISSUER: DEV, AWS_ENDPOINT_URL: 'file:///etc/passwd' }),
    /AWS_ENDPOINT_URL must be an http or https URL/,
  );
});

test('a plain http endpoint is development only', () => {
  // Local stacks are http, and that is the whole point of the override.
  const dev = loadConfig({ SAG_ISSUER: DEV, AWS_ENDPOINT_URL: 'http://localstack:4566' });
  assert.deepEqual(dev.problems, []);

  // Against a real name it is refused: SAG's requests would still be
  // unforgeable, but a KMS reply in clear is a signature anybody on the path
  // can replace, and an S3 reply is the relying party register itself.
  const real = loadConfig({
    SAG_ISSUER: 'https://id.example.com',
    SAG_SECRET: 'x'.repeat(48),
    SIGNING_PRIVATE_JWK: '{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"c"}',
    EMAIL_PROVIDER: 'ses',
    EMAIL_FROM: 'Sign in <no-reply@id.example.com>',
    SES_REGION: 'eu-west-2',
    SUBJECT_SALT: 'never-rotate-this',
    AWS_ENDPOINT_URL_DYNAMODB: 'http://dynamo.internal:8000',
  });
  assert.ok(real.problems.some((p) => /DynamoDB endpoint override is a plain http URL/.test(p)));

  // Over TLS it is somebody else's architecture, not a problem.
  const tls = loadConfig({
    SAG_ISSUER: 'https://id.example.com',
    SAG_SECRET: 'x'.repeat(48),
    SIGNING_PRIVATE_JWK: '{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"c"}',
    EMAIL_PROVIDER: 'ses',
    EMAIL_FROM: 'Sign in <no-reply@id.example.com>',
    SES_REGION: 'eu-west-2',
    SUBJECT_SALT: 'never-rotate-this',
    AWS_ENDPOINT_URL_DYNAMODB: 'https://dynamo.internal:8000',
  });
  assert.deepEqual(tls.problems, []);
});

// ---------------------------------------------------------------------------
// KMS
// ---------------------------------------------------------------------------

/** WebCrypto gives r||s; KMS returns SEQUENCE { INTEGER r, INTEGER s }. */
function rawToDer(raw) {
  const int = (bytes) => {
    let v = bytes;
    while (v.length > 1 && v[0] === 0) v = v.slice(1);
    if (v[0] & 0x80) v = Uint8Array.from([0, ...v]);
    return [0x02, v.length, ...v];
  };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
  return Uint8Array.from([0x30, body.length, ...body]);
}

/**
 * KMS, as far as SAG is concerned: two operations, and the wire formats that
 * matter - an SPKI public key and a DER signature.
 */
async function kmsStub() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  return fetchStub(async (url, init) => {
    const target = init.headers['x-amz-target'];
    const body = JSON.parse(init.body);
    if (target === 'TrentService.GetPublicKey') {
      return new Response(JSON.stringify({ KeyId: body.KeyId, PublicKey: Buffer.from(spki).toString('base64') }));
    }
    if (target === 'TrentService.Sign') {
      assert.equal(body.MessageType, 'RAW', 'KMS does the hashing, so the message goes over unhashed');
      assert.equal(body.SigningAlgorithm, 'ECDSA_SHA_256');
      const raw = new Uint8Array(
        await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(body.Message, 'base64')),
      );
      return new Response(JSON.stringify({ Signature: Buffer.from(rawToDer(raw)).toString('base64') }));
    }
    return new Response('{"__type":"UnsupportedOperationException"}', { status: 400 });
  });
}

test('the KMS signer talks to the endpoint it was given, and its signatures verify', async (t) => {
  const stub = await kmsStub();
  t.after(stub.restore);

  const config = loadConfig({
    SAG_ISSUER: DEV,
    SIGNING_BACKEND: 'aws-kms',
    SIGNING_KMS_KEY_ID: 'alias/sag-signing',
    SIGNING_KMS_REGION: 'eu-west-2',
    AWS_ENDPOINT_URL_KMS: 'http://localstack:4566',
  });
  assert.deepEqual(config.problems, []);

  const signer = await createSigner(config, awsEnv);
  const input = Buffer.from('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjMifQ', 'utf8');
  const signature = await signer.sign(input);

  // A JWS signature is r||s, so the DER KMS returned has to have been unpacked.
  assert.equal(signature.length, 64);

  const { keys } = await signer.publicJwks();
  const key = await crypto.subtle.importKey('jwk', { ...keys[0], ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  assert.ok(
    await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, input),
    'the published JWKS must verify what the signer produced',
  );
  assert.ok(keys[0].kid, 'a key with no kid cannot be rotated');

  for (const call of stub.calls) {
    assert.equal(call.url, 'http://localstack:4566', 'every call goes to the override, not to AWS');
    assert.match(call.init.headers.authorization, /^AWS4-HMAC-SHA256 .*\/eu-west-2\/kms\/aws4_request/);
  }
  // The public key is fetched once and cached: it is the same key every time,
  // and the JWKS endpoint is on the hot path.
  assert.equal(stub.calls.filter((c) => c.init.headers['x-amz-target'].endsWith('GetPublicKey')).length, 1);
});

// ---------------------------------------------------------------------------
// DynamoDB and S3
// ---------------------------------------------------------------------------

test('the state store writes to the endpoint it was given', async (t) => {
  const stub = fetchStub(() => new Response('{}', { status: 200 }));
  t.after(stub.restore);

  const config = loadConfig({
    SAG_ISSUER: DEV,
    STATE_STORE_BACKEND: 'dynamodb',
    STATE_STORE_TABLE: 'sag-state',
    STATE_STORE_REGION: 'eu-west-2',
    AWS_ENDPOINT_URL_DYNAMODB: 'http://localstack:4566',
  });
  const store = await createStateStore(config, awsEnv);
  assert.equal(await store.claim('code-1', 120), true);

  assert.equal(stub.calls[0].url, 'http://localstack:4566');
  // The region is still part of the signature's scope, so an emulator has to
  // agree about it even though it is not in the hostname any more.
  assert.match(stub.calls[0].init.headers.authorization, /\/eu-west-2\/dynamodb\/aws4_request/);
});

test('an overridden S3 endpoint is addressed path style', async (t) => {
  const record = {
    client_name: 'Ledger',
    redirect_uris: ['https://ledger.example.com/auth/callback'],
  };
  const stub = fetchStub(() => new Response(JSON.stringify(record), { status: 200 }));
  t.after(stub.restore);

  const config = loadConfig({
    SAG_ISSUER: DEV,
    CLIENTS_STORE_BACKEND: 's3',
    CLIENTS_STORE_S3_BUCKET: 'sag-clients',
    CLIENTS_STORE_S3_REGION: 'eu-west-2',
    AWS_ENDPOINT_URL_S3: 'http://localstack:4566',
  });
  const store = await createClientStore(config, awsEnv);
  const client = await store.get('ledger');
  assert.equal(client.clientName, 'Ledger');

  // A bucket cannot be a subdomain of a hostname that is not S3's, which is
  // the whole reason this switch exists.
  assert.equal(stub.calls[0].url, 'http://localstack:4566/sag-clients/clients/ledger.json');
  assert.match(stub.calls[0].init.headers.authorization, /\/eu-west-2\/s3\/aws4_request/);
});

test('without an override, S3 is still addressed as a virtual host', async (t) => {
  const stub = fetchStub(() => new Response('{}', { status: 404 }));
  t.after(stub.restore);

  const config = loadConfig({
    SAG_ISSUER: DEV,
    CLIENTS_STORE_BACKEND: 's3',
    CLIENTS_STORE_S3_BUCKET: 'sag-clients',
    CLIENTS_STORE_S3_REGION: 'eu-west-2',
  });
  const store = await createClientStore(config, awsEnv);
  assert.equal(await store.get('ledger'), undefined);
  assert.equal(stub.calls[0].url, 'https://sag-clients.s3.eu-west-2.amazonaws.com/clients/ledger.json');
});
