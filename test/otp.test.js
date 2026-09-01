// The one-time code itself.
//
// The attempt counter travels inside the sealed transaction, and a person can
// present an older copy of one, so the counter deters casual retrying rather
// than preventing brute force. What actually makes guessing hopeless is the
// size of the keyspace, which is why these properties are pinned by tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, extractField, extractDevCode, authorizeUrl, pkce } from './harness.js';
import { generateCode, normaliseCode, formatCodeForDisplay, CODE_ALPHABETS, alphabetFor } from '../src/otp.js';
import { loadConfig } from '../src/config.js';

test('the alphabet has no character that can be mistaken for another', async () => {
  // 0/O and 1/I/L are the pairs people mistype reading a code off a screen.
  // Both members of each pair are absent, so there is nothing to substitute.
  for (const c of '01OIL') {
    assert.ok(!CODE_ALPHABETS.alphanumeric.includes(c), c + ' must not be in the alphabet');
  }
  // U is out as well, so nine random characters cannot spell something
  // unfortunate at somebody.
  assert.ok(!CODE_ALPHABETS.alphanumeric.includes('U'));
  assert.equal(new Set(CODE_ALPHABETS.alphanumeric).size, CODE_ALPHABETS.alphanumeric.length);
});

test('a code is nine characters from that alphabet by default', () => {
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  assert.equal(config.otp.codeLength, 9);
  assert.equal(config.otp.codeAlphabet, 'alphanumeric');

  const code = generateCode(config.otp.codeLength, alphabetFor(config));
  assert.equal(code.length, 9);
  assert.match(code, /^[23456789A-HJKMNP-TV-Z]{9}$/);
});

test('nine characters is roughly two thousand times a six digit code', () => {
  // 30^9 against 10^6. This is the whole argument for the change: guessing is
  // hopeless even with an attempt counter that can be rolled back.
  const keyspace = Math.pow(CODE_ALPHABETS.alphanumeric.length, 9);
  assert.ok(keyspace / 1e6 > 1e7, 'keyspace ratio: ' + keyspace / 1e6);
});

test('generation is not biased towards the start of the alphabet', () => {
  // A modulo over 256 would favour the first symbols, which quietly shrinks
  // the keyspace. Rejection sampling avoids it, and a rough count catches a
  // regression that reintroduces the bias.
  const counts = new Map();
  for (let i = 0; i < 400; i++) {
    for (const c of generateCode(9)) counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  const expected = 3600 / CODE_ALPHABETS.alphanumeric.length;
  for (const symbol of CODE_ALPHABETS.alphanumeric) {
    const seen = counts.get(symbol) ?? 0;
    assert.ok(seen > expected / 3, symbol + ' appeared ' + seen + ' times, expected about ' + Math.round(expected));
  }
});

test('what somebody types is folded, but nothing is silently substituted', () => {
  assert.equal(normaliseCode(' k4m-9pq rt '), 'K4M9PQRT');
  assert.equal(normaliseCode('abc def ghj'), 'ABCDEFGHJ');
  assert.equal(normaliseCode(undefined), '');
  // O and 1 were never issued, so a code containing one is simply wrong.
  assert.equal(normaliseCode('O1'), 'O1');
});

test('a code is grouped so it can be read back from an email', () => {
  assert.equal(formatCodeForDisplay('K4M9PQRTV'), 'K4M 9PQ RTV');
  assert.equal(formatCodeForDisplay('12345678'), '1234 5678');
});

test('the page accepts the code in whatever shape it was copied', async () => {
  const sag = createInstance();
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge });
  const first = await sag.raw(path);
  const sent = await sag.postForm('/authorize/email', {
    tx: extractField(await first.text()),
    email: 'person@example.org',
  });
  const html = await sent.text();
  const code = extractDevCode(html);

  const done = await sag.postForm('/authorize/otp', {
    tx: extractField(html),
    // Lower case with the spacing from the email, which is what a paste
    // usually looks like.
    code: ' ' + formatCodeForDisplay(code).toLowerCase() + ' ',
  });
  assert.equal(done.status, 303, 'a pasted code must not be rejected on whitespace');
});

test('a code shorter than nine characters is raised, and said out loud', () => {
  // Six digits with a rollback-able attempt counter is a one in a million
  // guess per attempt and unlimited attempts, so it is not offered. Refusing
  // to start would be a worse failure on upgrade than a longer code, so a
  // deployment that pinned the old default is raised and told.
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787', OTP_CODE_LENGTH: '6' });
  assert.equal(config.otp.codeLength, 9);
  assert.ok(config.internalWarnings.some((w) => /below the minimum of 9/.test(w)));
});

test('somebody who asked for digits gets digits', () => {
  // OTP_DIGITS was the old name and it meant digits, so honouring the name
  // has to mean honouring what it said.
  const numeric = loadConfig({ SAG_ISSUER: 'http://localhost:8787', OTP_DIGITS: '10' });
  assert.equal(numeric.otp.codeLength, 10);
  assert.equal(alphabetFor(numeric), CODE_ALPHABETS.numeric);
  const overridden = loadConfig({
    SAG_ISSUER: 'http://localhost:8787',
    OTP_DIGITS: '10',
    OTP_CODE_ALPHABET: 'alphanumeric',
  });
  assert.equal(alphabetFor(overridden), CODE_ALPHABETS.alphanumeric, 'unless they have since said otherwise');
});
