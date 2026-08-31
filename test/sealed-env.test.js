// Sealed environment variables: a value pasted as `aws:kms:<ciphertext>`,
// `aws:secretsmanager:<secret id>` or `aws:ssm:<name>` is resolved before
// configuration is parsed, so a secret never has to sit in plain text in a
// deploy account's environment variables.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { unsealEnv } from '../src/keys/sealedEnv.js';
import { loadConfig } from '../src/config.js';

const awsEnv = { AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE', AWS_SECRET_ACCESS_KEY: 'secret', AWS_REGION: 'eu-west-2' };

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

/** One stub that answers whichever of the three services is asked. */
function awsSecretsStub({ kms = {}, secretsmanager = {}, ssm = {} } = {}) {
  return fetchStub(async (url, init) => {
    const target = init.headers['x-amz-target'];
    const body = JSON.parse(init.body);
    if (target === 'TrentService.Decrypt') {
      const plaintext = kms[body.CiphertextBlob];
      if (!plaintext) return new Response('{"__type":"InvalidCiphertextException"}', { status: 400 });
      return new Response(JSON.stringify({ Plaintext: Buffer.from(plaintext, 'utf8').toString('base64') }));
    }
    if (target === 'secretsmanager.GetSecretValue') {
      const value = secretsmanager[body.SecretId];
      if (!value) return new Response('{"__type":"ResourceNotFoundException"}', { status: 400 });
      return new Response(JSON.stringify({ SecretString: value }));
    }
    if (target === 'AmazonSSM.GetParameter') {
      assert.equal(body.WithDecryption, true, 'a SecureString must be requested with decryption');
      const value = ssm[body.Name];
      if (!value) return new Response('{"__type":"ParameterNotFound"}', { status: 400 });
      return new Response(JSON.stringify({ Parameter: { Value: value } }));
    }
    return new Response('{"__type":"UnsupportedOperationException"}', { status: 400 });
  });
}

test('an env with nothing sealed passes through untouched, with no AWS call', async () => {
  const stub = fetchStub(() => {
    throw new Error('must not call AWS when nothing is sealed');
  });
  try {
    const env = { SAG_ISSUER: 'http://localhost:8787', SOME_SECRET: 'plain-value' };
    const result = await unsealEnv(env);
    assert.equal(result, env, 'unchanged input returns the same reference');
  } finally {
    stub.restore();
  }
});

test('an aws:kms:-prefixed value is decrypted and the rest of the bag is left alone', async (t) => {
  const stub = awsSecretsStub({ kms: { 'AQICAHhceyphertext==': 'super-secret-value' } });
  t.after(stub.restore);

  const result = await unsealEnv({
    ...awsEnv,
    UPSTREAM_MICROSOFT_COMMON_CLIENT_SECRET: 'aws:kms:AQICAHhceyphertext==',
    UNRELATED: 'unchanged',
  });

  assert.equal(result.UPSTREAM_MICROSOFT_COMMON_CLIENT_SECRET, 'super-secret-value');
  assert.equal(result.UNRELATED, 'unchanged');
  assert.equal(stub.calls[0].url, 'https://kms.eu-west-2.amazonaws.com/');
  assert.match(stub.calls[0].init.headers.authorization, /\/eu-west-2\/kms\/aws4_request/);
});

test('aws:secretsmanager: resolves a secret by id, ARN colons and all', async (t) => {
  const arn = 'arn:aws:secretsmanager:eu-west-2:123456789012:secret:sag/upstream-AbCdEf';
  const stub = awsSecretsStub({ secretsmanager: { [arn]: 'from-secrets-manager' } });
  t.after(stub.restore);

  const result = await unsealEnv({ ...awsEnv, SECRET: 'aws:secretsmanager:' + arn });
  assert.equal(result.SECRET, 'from-secrets-manager');
  assert.equal(stub.calls[0].url, 'https://secretsmanager.eu-west-2.amazonaws.com/');
});

test('aws:ssm: resolves a parameter by name, with decryption requested', async (t) => {
  const stub = awsSecretsStub({ ssm: { '/sag/upstream-secret': 'from-ssm' } });
  t.after(stub.restore);

  const result = await unsealEnv({ ...awsEnv, SECRET: 'aws:ssm:/sag/upstream-secret' });
  assert.equal(result.SECRET, 'from-ssm');
  assert.equal(stub.calls[0].url, 'https://ssm.eu-west-2.amazonaws.com/');
});

test('several sealed values from different services in the same bag are all resolved', async (t) => {
  const stub = awsSecretsStub({
    kms: { 'kms-cipher-a': 'value-a' },
    secretsmanager: { 'my-secret': 'value-b' },
    ssm: { '/my/param': 'value-c' },
  });
  t.after(stub.restore);

  const result = await unsealEnv({
    ...awsEnv,
    ONE: 'aws:kms:kms-cipher-a',
    TWO: 'aws:secretsmanager:my-secret',
    THREE: 'aws:ssm:/my/param',
    FOUR: 'plain',
  });

  assert.equal(result.ONE, 'value-a');
  assert.equal(result.TWO, 'value-b');
  assert.equal(result.THREE, 'value-c');
  assert.equal(result.FOUR, 'plain');
  assert.equal(stub.calls.length, 3);
});

test('each service honours its own endpoint override, same as the signer and the stores', async (t) => {
  const stub = awsSecretsStub({
    kms: { a: 'value-a' },
    secretsmanager: { b: 'value-b' },
    ssm: { c: 'value-c' },
  });
  t.after(stub.restore);

  const result = await unsealEnv({
    ...awsEnv,
    AWS_ENDPOINT_URL_KMS: 'http://localstack-kms:4566',
    AWS_ENDPOINT_URL_SECRETS_MANAGER: 'http://localstack-sm:4566',
    AWS_ENDPOINT_URL_SSM: 'http://localstack-ssm:4566',
    ONE: 'aws:kms:a',
    TWO: 'aws:secretsmanager:b',
    THREE: 'aws:ssm:c',
  });

  assert.equal(result.ONE, 'value-a');
  assert.equal(result.TWO, 'value-b');
  assert.equal(result.THREE, 'value-c');
  assert.equal(stub.calls.find((c) => c.init.headers['x-amz-target'] === 'TrentService.Decrypt').url, 'http://localstack-kms:4566');
  assert.equal(
    stub.calls.find((c) => c.init.headers['x-amz-target'] === 'secretsmanager.GetSecretValue').url,
    'http://localstack-sm:4566',
  );
  assert.equal(stub.calls.find((c) => c.init.headers['x-amz-target'] === 'AmazonSSM.GetParameter').url, 'http://localstack-ssm:4566');
});

test('a sealed value with no region configured is refused rather than left unresolved', async () => {
  await assert.rejects(
    () => unsealEnv({ AWS_ACCESS_KEY_ID: 'x', AWS_SECRET_ACCESS_KEY: 'y', SECRET: 'aws:kms:ciphertext' }),
    /AWS_REGION must be set/,
  );
});

test('a failure is fatal, never silently falls back to the reference itself', async (t) => {
  const stub = fetchStub(() => new Response('{"__type":"AccessDeniedException"}', { status: 400 }));
  t.after(stub.restore);

  await assert.rejects(() => unsealEnv({ ...awsEnv, SECRET: 'aws:kms:ciphertext' }), /kms TrentService\.Decrypt failed/);
  await assert.rejects(
    () => unsealEnv({ ...awsEnv, SECRET: 'aws:secretsmanager:my-secret' }),
    /secretsmanager secretsmanager\.GetSecretValue failed/,
  );
  await assert.rejects(() => unsealEnv({ ...awsEnv, SECRET: 'aws:ssm:/my/param' }), /ssm AmazonSSM\.GetParameter failed/);
});

test('loadConfig refuses a still-sealed value rather than treating the reference as the secret', () => {
  // A shape check alone would not catch this: a base64 ciphertext blob or a
  // secret ARN is easily long enough to pass "SAG_SECRET must be at least
  // 32 characters".
  for (const value of ['aws:kms:AQICAHhceyphertext==', 'aws:secretsmanager:sag/secret', 'aws:ssm:/sag/secret']) {
    assert.throws(
      () => loadConfig({ SAG_ISSUER: 'http://localhost:8787', SAG_SECRET: value }),
      /SAG_SECRET is still sealed/,
    );
  }
});
