// Invariants over the broad input spaces behind SAG's stateless tokens.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { seal, SealError, unseal } from '../src/crypto/secrets.js';
import { normaliseEmail, stripPlusTag } from '../src/identity.js';
import { b64, b64u, fromHex, toHex, unb64, unb64u } from '../src/util/bytes.js';

const SECRET = 'property-test-secret-'.repeat(3);

test('binary text encodings round-trip arbitrary bytes', () => {
  fc.assert(
    fc.property(fc.uint8Array({ maxLength: 4096 }), (bytes) => {
      assert.deepEqual(unb64u(b64u(bytes)), bytes);
      assert.deepEqual(unb64(b64(bytes)), bytes);
      assert.deepEqual(fromHex(toHex(bytes)), bytes);
      assert.match(b64u(bytes), /^[A-Za-z0-9_-]*$/);
    }),
  );
});

test('sealing round-trips arbitrary JSON data', async () => {
  await fc.assert(
    fc.asyncProperty(fc.jsonValue(), async (value) => {
      const payload = { value };
      const token = await seal(SECRET, 'property', payload);
      const opened = await unseal(SECRET, 'property', token);
      assert.deepEqual(opened, JSON.parse(JSON.stringify(payload)));
    }),
    { numRuns: 50 },
  );
});

test('changing any generated ciphertext bit is detected', async () => {
  await fc.assert(
    fc.asyncProperty(fc.jsonValue(), fc.nat(), fc.integer({ min: 0, max: 7 }), async (value, offset, bit) => {
      const token = await seal(SECRET, 'property', { value });
      const parts = token.split('.');
      const ciphertext = unb64u(parts[3]);
      ciphertext[offset % ciphertext.length] ^= 1 << bit;
      parts[3] = b64u(ciphertext);
      await assert.rejects(() => unseal(SECRET, 'property', parts.join('.')), SealError);
    }),
    { numRuns: 50 },
  );
});

test('identity canonicalisers are idempotent for arbitrary text', () => {
  fc.assert(
    fc.property(fc.string(), (input) => {
      const normalised = normaliseEmail(input);
      assert.equal(normaliseEmail(normalised), normalised);

      const untagged = stripPlusTag(input);
      assert.equal(stripPlusTag(untagged), untagged);
    }),
  );
});
