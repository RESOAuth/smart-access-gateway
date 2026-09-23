import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ACR, minimumStrengthRequired, requiresFederation, satisfies } from '../src/acr.js';
import { decodeJwt } from '../src/crypto/jose.js';
import { authorizeUrl, createInstance, extractField, pkce, redeem, signInWithOtp } from './harness.js';

test('a method-neutral MFA request accepts only established local or federated MFA', () => {
  for (const held of [ACR.LOCAL_MFA, ACR.FEDERATED_MFA]) {
    assert.equal(satisfies(held, [ACR.MFA]), true, held);
  }
  for (const held of [ACR.OTP, ACR.LOCAL_PASSWORD, ACR.FEDERATED, ACR.MFA, 'unknown', undefined]) {
    assert.equal(satisfies(held, [ACR.MFA]), false, held);
  }

  assert.equal(satisfies(ACR.LOCAL_MFA, [ACR.FEDERATED_MFA]), false);
  assert.equal(satisfies(ACR.FEDERATED_MFA, [ACR.LOCAL_MFA]), false);
  assert.equal(satisfies(ACR.LOCAL_MFA, [ACR.FEDERATED_MFA, ACR.MFA]), true);
  assert.equal(satisfies(ACR.FEDERATED_MFA, [ACR.LOCAL_MFA, ACR.MFA]), true);
  assert.equal(satisfies(ACR.OTP, [ACR.MFA, ACR.OTP]), true);
  assert.equal(satisfies(ACR.FEDERATED, [ACR.MFA, ACR.FEDERATED]), true);
  assert.equal(satisfies(ACR.LOCAL_PASSWORD, [ACR.MFA, ACR.LOCAL_PASSWORD]), true);
});

test('MFA routing excludes email OTP unless the request includes an email-compatible alternative', () => {
  assert.equal(minimumStrengthRequired([ACR.MFA]), 3);
  assert.equal(requiresFederation([ACR.MFA]), true);
  assert.equal(requiresFederation([ACR.MFA, ACR.LOCAL_PASSWORD]), true);
  assert.equal(requiresFederation([ACR.MFA, ACR.FEDERATED]), true);
  assert.equal(requiresFederation([ACR.MFA, ACR.OTP]), false);
});

test('a standalone email code cannot answer a method-neutral MFA request', async () => {
  const sag = createInstance();
  const { challenge } = await pkce();
  const { path, params } = authorizeUrl({ challenge, acr_values: ACR.MFA });
  const first = await sag.raw(path);
  const routed = await sag.postForm('/authorize/email', {
    tx: extractField(await first.text()),
    email: 'jamie.taylor@example.test',
  });
  assert.equal(routed.status, 303);
  const location = new URL(routed.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'unmet_authentication_requirements');
  assert.equal(location.searchParams.get('state'), params.get('state'));
  assert.equal(location.searchParams.has('code'), false);
});

test('an explicit email-code alternative still works alongside a method-neutral MFA request', async () => {
  const sag = createInstance();
  const result = await signInWithOtp(sag, {
    email: 'jamie.taylor@example.test',
    authorize: { acr_values: ACR.MFA + ' ' + ACR.OTP },
  });
  const tokens = await redeem(sag, result);
  assert.equal(tokens.res.status, 200);
  assert.equal(decodeJwt(tokens.body.id_token).payload.acr, ACR.OTP);
});
