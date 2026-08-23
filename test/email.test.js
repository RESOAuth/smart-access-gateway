// The email senders, and the MIME assembly two of them depend on.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildMimeMessage, quotedPrintable, encodeHeaderValue, parseAddress } from '../src/email/mime.js';
import { parseNotifyKey, createNotifySender } from '../src/email/notify.js';
import { parseSmtpUrl } from '../src/email/smtp.js';
import { createSesSender } from '../src/email/ses.js';
import { createMailchannelsSender } from '../src/email/mailchannels.js';
import { createEmailSender } from '../src/email/index.js';
import { otpMessage } from '../src/email/message.js';
import { loadConfig } from '../src/config.js';
import { decodeJwt } from '../src/crypto/jose.js';

const baseEnv = { SAG_ISSUER: 'https://id.example.com', SAG_SECRET: 'x'.repeat(48) };
const configWith = (env) => loadConfig({ ...baseEnv, ...env });

/** Capture whatever a sender sends, without touching the network. */
function captureFetch() {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    calls.push({ url: typeof input === 'string' ? input : input.url, init });
    return new Response(JSON.stringify({ MessageId: 'stub-id', id: 'stub-id' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return {
    calls,
    restore: () => {
      globalThis.fetch = real;
    },
  };
}

test('addresses are parsed and reformatted', () => {
  assert.deepEqual(parseAddress('Someone <a@b.test>'), { name: 'Someone', address: 'a@b.test' });
  assert.deepEqual(parseAddress('"Sign in" <a@b.test>'), { name: 'Sign in', address: 'a@b.test' });
  assert.deepEqual(parseAddress('a@b.test'), { address: 'a@b.test' });
});

test('a non-ASCII header is encoded, an ASCII one is left alone', () => {
  assert.equal(encodeHeaderValue('Your sign-in code'), 'Your sign-in code');
  assert.match(encodeHeaderValue('Cyfrinair Mêr'), /^=\?UTF-8\?B\?/);
});

test('quoted-printable escapes what it must and wraps long lines', () => {
  assert.equal(quotedPrintable('plain text'), 'plain text');
  assert.equal(quotedPrintable('a=b'), 'a=3Db');
  // Trailing whitespace before a break has to become an escape, or a relay
  // strips it and the body no longer matches what was signed.
  assert.equal(quotedPrintable('trailing \nnext'), 'trailing=20\r\nnext');
  assert.equal(quotedPrintable('tab\t\nnext'), 'tab=09\r\nnext');
  const long = quotedPrintable('x'.repeat(200));
  for (const line of long.split('\r\n')) assert.ok(line.length <= 76, 'line too long: ' + line.length);
});

test('a MIME message carries both alternatives and suppresses auto-replies', () => {
  const msg = otpMessage({ code: '123456', ttlMinutes: 10, issuerHost: 'id.example.com' });
  const raw = buildMimeMessage({
    to: 'person@example.org',
    from: 'Sign in <no-reply@id.example.com>',
    subject: msg.subject,
    text: msg.text,
    html: msg.html,
    date: new Date('2026-01-01T00:00:00Z'),
  });

  assert.match(raw, /^From: "Sign in" <no-reply@id\.example\.com>\r\n/);
  assert.match(raw, /\r\nTo: person@example\.org\r\n/);
  assert.match(raw, /\r\nContent-Type: multipart\/alternative; boundary="sag-[A-Za-z0-9]+"\r\n/);
  // A one-time code must not trigger an out-of-office reply.
  assert.match(raw, /\r\nAuto-Submitted: auto-generated\r\n/);
  assert.match(raw, /\r\nX-Auto-Response-Suppress: All\r\n/);
  assert.match(raw, /Content-Type: text\/plain; charset=UTF-8/);
  assert.match(raw, /Content-Type: text\/html; charset=UTF-8/);
  assert.ok(raw.indexOf('text/plain') < raw.indexOf('text/html'), 'plain text must come first');
  assert.ok(!raw.includes('\n\n'), 'every break must be CRLF');
});

test('the message never contains a link, so it cannot be phished by forwarding', () => {
  const msg = otpMessage({ code: '123456', ttlMinutes: 10, issuerHost: 'id.example.com', clientName: 'Ledger' });
  assert.ok(!/href=/i.test(msg.html), 'no links at all');
  assert.match(msg.text, /123 456/, 'the code is grouped for reading aloud');
  assert.match(msg.text, /Ledger/, 'it says which application asked');
  assert.match(msg.subject, /123 456/);
});

test('a GOV.UK Notify key is split into service id and secret', () => {
  const serviceId = '11111111-2222-3333-4444-555555555555';
  const secret = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const parsed = parseNotifyKey('sag-live-' + serviceId + '-' + secret);
  assert.equal(parsed.serviceId, serviceId);
  assert.equal(parsed.secret, secret);
  assert.throws(() => parseNotifyKey('too-short'), /too short/);
  assert.throws(() => parseNotifyKey('x'.repeat(80)), /expected/);
});

test('Notify is called with a signed JWT and personalisation, not a body', async (t) => {
  const serviceId = '11111111-2222-3333-4444-555555555555';
  const secret = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const config = configWith({
    EMAIL_PROVIDER: 'notify',
    EMAIL_FROM: 'no-reply@id.example.com',
    NOTIFY_API_KEY: 'sag-live-' + serviceId + '-' + secret,
    NOTIFY_TEMPLATE_ID: 'template-1',
  });
  const capture = captureFetch();
  t.after(capture.restore);

  const sender = createNotifySender(config);
  await sender.send({ to: 'person@example.org', code: '123456', ttlMinutes: 10 });

  assert.equal(capture.calls.length, 1);
  const call = capture.calls[0];
  assert.equal(call.url, 'https://api.notifications.service.gov.uk/v2/notifications/email');
  const auth = call.init.headers.authorization;
  assert.match(auth, /^Bearer /);
  const { payload } = decodeJwt(auth.slice(7));
  assert.equal(payload.iss, serviceId, 'the service id is the issuer');
  assert.ok(payload.iat, 'a timestamp bounds how long the request is replayable');

  const body = JSON.parse(call.init.body);
  assert.equal(body.template_id, 'template-1');
  assert.equal(body.email_address, 'person@example.org');
  assert.equal(body.personalisation.code, '123456');
  assert.equal(body.personalisation.ttl_minutes, 10);
});

test('SES is called with a SigV4 signature and both body parts', async (t) => {
  const config = configWith({
    EMAIL_PROVIDER: 'ses',
    EMAIL_FROM: 'Sign in <no-reply@id.example.com>',
    SES_REGION: 'eu-west-2',
    SES_CONFIGURATION_SET: 'sag',
  });
  const capture = captureFetch();
  t.after(capture.restore);

  const sender = createSesSender(config, {
    AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'secret',
  });
  await sender.send({ to: 'person@example.org', subject: 'Your code', text: 'plain', html: '<p>rich</p>' });

  const call = capture.calls[0];
  assert.equal(call.url, 'https://email.eu-west-2.amazonaws.com/v2/email/outbound-emails');
  assert.match(call.init.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\/\d{8}\/eu-west-2\/ses\/aws4_request/);
  assert.match(call.init.headers.authorization, /SignedHeaders=[a-z0-9;-]+/);
  const body = JSON.parse(call.init.body);
  assert.equal(body.Destination.ToAddresses[0], 'person@example.org');
  assert.equal(body.Content.Simple.Body.Text.Data, 'plain');
  assert.equal(body.Content.Simple.Body.Html.Data, '<p>rich</p>');
  assert.equal(body.ConfigurationSetName, 'sag', 'bounce reporting must be wired up');
});

test('SES refuses to start without a region or a from address', () => {
  assert.throws(() => createSesSender(configWith({ EMAIL_PROVIDER: 'ses', EMAIL_FROM: 'a@b.test' }), {}), /REGION/);
});

test('MailChannels sends plain text before HTML', async (t) => {
  const config = configWith({
    EMAIL_PROVIDER: 'mailchannels',
    EMAIL_FROM: 'Sign in <no-reply@id.example.com>',
    MAILCHANNELS_API_KEY: 'key-1',
  });
  const capture = captureFetch();
  t.after(capture.restore);

  const sender = createMailchannelsSender(config);
  await sender.send({ to: 'person@example.org', subject: 'Your code', text: 'plain', html: '<p>rich</p>' });

  const call = capture.calls[0];
  assert.equal(call.init.headers['x-api-key'], 'key-1');
  const body = JSON.parse(call.init.body);
  assert.equal(body.from.email, 'no-reply@id.example.com');
  assert.equal(body.from.name, 'Sign in');
  // A client picks the last part it understands, so plain text must be first.
  assert.equal(body.content[0].type, 'text/plain');
  assert.equal(body.content[1].type, 'text/html');
});

test('an SMTP URL is parsed with safe defaults', () => {
  const plain = parseSmtpUrl('smtp://user:pass@relay.example:2525');
  assert.deepEqual(plain, {
    host: 'relay.example',
    port: 2525,
    secure: false,
    username: 'user',
    password: 'pass',
    rejectUnauthorized: true,
    requireTls: true,
  });
  assert.equal(parseSmtpUrl('smtps://relay.example').port, 465, 'implicit TLS defaults to 465');
  assert.equal(parseSmtpUrl('smtp://relay.example').port, 587, 'submission defaults to 587');
  assert.equal(parseSmtpUrl('smtp://relay.example?insecure=true').rejectUnauthorized, false);
  assert.throws(() => parseSmtpUrl('https://relay.example'), /smtp/);
});

test('the sender registry loads each provider lazily and rejects unknown ones', async () => {
  const console_ = await createEmailSender(configWith({}), {});
  assert.equal(console_.name, 'console');

  const mailchannels = await createEmailSender(
    configWith({ EMAIL_PROVIDER: 'mailchannels', EMAIL_FROM: 'a@b.test' }),
    {},
  );
  assert.equal(mailchannels.name, 'mailchannels');

  // An unknown provider is caught by config validation first, so reaching the
  // registry with one means something went badly wrong.
  await assert.rejects(
    createEmailSender({ ...configWith({}), email: { provider: 'carrier-pigeon' } }, {}),
    /unknown EMAIL_PROVIDER/,
  );
});

test('the console sender prints the code, and returns it only in development', async (t) => {
  // The banner is captured rather than allowed out: a test that writes blocks
  // of text to stdout while the runner is multiplexing several files at once
  // has been seen to kill the file it is in, and the assertion is better made
  // on the captured text anyway.
  const printed = [];
  const real = console.log;
  console.log = (...args) => printed.push(args.join(' '));
  t.after(() => {
    console.log = real;
  });

  const dev = await createEmailSender(loadConfig({ SAG_ISSUER: 'http://localhost:8787' }), {});
  const devResult = await dev.send({ to: 'a@b.test', subject: 's', code: 'K4M9PQRTV' });
  assert.equal(devResult.code, 'K4M9PQRTV', 'the dev UI shows the code on the page');
  const banner = printed.join('\n');
  assert.match(banner, /CODE:\s+K4M9PQRTV/, 'a developer has to be able to read it off the log');
  assert.match(banner, /a@b\.test/);
  assert.match(banner, /not actually sent/, 'and must not think it was delivered');

  const prod = await createEmailSender(
    { ...configWith({}), devMode: false, email: { provider: 'console' } },
    {},
  );
  const prodResult = await prod.send({ to: 'a@b.test', subject: 's', code: 'K4M9PQRTV' });
  assert.equal(prodResult.code, undefined, 'never on a real deployment');
});

test('a real hostname refuses to run on the console sender', () => {
  const config = loadConfig({ SAG_ISSUER: 'https://id.example.com', SAG_SECRET: 'x'.repeat(48) });
  assert.ok(
    config.problems.some((p) => /EMAIL_PROVIDER is "console"/.test(p)),
    'printing codes to a log is not a delivery mechanism',
  );
});
