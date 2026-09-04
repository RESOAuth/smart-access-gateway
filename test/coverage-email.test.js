// Additional coverage tests for src/email/*.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import tls from 'node:tls';
import { loadConfig } from '../src/config.js';
import { createMailchannelsSender } from '../src/email/mailchannels.js';
import { createNotifySender } from '../src/email/notify.js';
import { createSesSender } from '../src/email/ses.js';
import { createSmtpSender } from '../src/email/smtp.js';
import { createCloudflareSender } from '../src/email/cloudflare.js';
import { createEmailSender, isConsoleSender } from '../src/email/index.js';
import { otpMessage } from '../src/email/message.js';
import { buildMimeMessage, formatAddress } from '../src/email/mime.js';

const baseEnv = { SAG_ISSUER: 'https://id.example.com', SAG_SECRET: 'x'.repeat(48) };
const configWith = (env) => loadConfig({ ...baseEnv, ...env });

const testCert = `-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUIEgPAydBFPNFUhVh0Dk4+41UDZ4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMCAXDTI2MDkwNDE2MDczNloYDzIxMjYw
ODExMTYwNzM2WjAUMRIwEAYDVQQDDAkxMjcuMC4wLjEwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC/zldYybgrqO7pVC9R5G5qph8FSAih8PGbD8qMWp4M
vMu8592dIUn3ulQ/syrFaW+eljiXS5A96w9v4ErI/cSRW6FLroiHLJKg+Wsm+4lX
BwksW286E6xUV+Lcs5oav5K7iKLK7v3XlzZKwLns2Gc4BvWkcZFUwlo1c4xWXm/x
hrqIxiFZeZ9uSFSRizsx928RXFrWjagGahV6LFAEoNJhHJMNKmPT11Oxejylx0y/
JrTtLToULXFx2TBca7bCOpYYRHSb836vyzikBJVTsGcQw0EBCteHLTBLVcYSuRV5
/wmCxt/QZMpW4UXQ1TGgPASKoKFO7HBq3VPHC6gNg6U5AgMBAAGjUzBRMB0GA1Ud
DgQWBBQ/HWSaDlPIg5hJiiqSfYdx5jfKOTAfBgNVHSMEGDAWgBQ/HWSaDlPIg5hJ
iiqSfYdx5jfKOTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAr
7/E8DdkTTPhhOVbPHYLE3EQjhgBx//FOzNMwew/m1iX1xm17FmNlSjd5/5E95/3f
vZcTzg6qo+4WIwXP5KRkmshGXcrSwOe5KpWCzM3qpvkGMHcCLGwHbk1t1LjvhW1O
iRGe5I07Ek2J11x1weWaeAMkW6sDhJGRbAVS+onsRairV5fNEGTDQNgHjf/wB8hc
UqCkNEj2mPynY1UfTDZKGwWxWOAn1lluBuv2JoqDEFVDrRs8SD4fe/cbF9PKgaZ2
6obCLaO2DFSdbSKJiA7vXILf4+dU0ZwomTfzgEXsPxZadI6Fq45THooUhisC18Wh
zV5ekBbjRygK4xTuGtlf
-----END CERTIFICATE-----`;

const testKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/zldYybgrqO7p
VC9R5G5qph8FSAih8PGbD8qMWp4MvMu8592dIUn3ulQ/syrFaW+eljiXS5A96w9v
4ErI/cSRW6FLroiHLJKg+Wsm+4lXBwksW286E6xUV+Lcs5oav5K7iKLK7v3XlzZK
wLns2Gc4BvWkcZFUwlo1c4xWXm/xhrqIxiFZeZ9uSFSRizsx928RXFrWjagGahV6
LFAEoNJhHJMNKmPT11Oxejylx0y/JrTtLToULXFx2TBca7bCOpYYRHSb836vyzik
BJVTsGcQw0EBCteHLTBLVcYSuRV5/wmCxt/QZMpW4UXQ1TGgPASKoKFO7HBq3VPH
C6gNg6U5AgMBAAECggEAC7frlj0cx24WyqKeEX7HUDS+CHCSNnKmEDcyxMh0h4qx
V+VCoOr7vergYtPrdQwwCZxb8MJpGZ9W3hrx9r2qWMckX59WMAwFGVijt0n+5hZD
9TXQ4dd5291SuvEuJRw3NsXuTD+1uoo+guqrcVD3XXDvaRCXNHp7UHCyzkQOys65
FBJnTmIoHA5LwnFqfe7spanf7qSAtS/VHI1aeTposrZa1h6Jdf37rKwkqsxZ+ea0
IyeRdVHy/YPUNayulQ72LfPoYtN1k9ArgnsUUKoy0Z4D5bUPIc3YdTw9ruuXyWym
osfjdyd/tVnsW9WJ1kuTz+LVu0PYsL70Ll0VkilDQQKBgQD/rjd5rTy9yRzTwvbi
S5zt73T/aEmmyVQSfHA9eV7ftWz+xVMcHu/nQjw8dpMc8SP/PRKPXlz3QtxtPuMS
4e+L/QaHXxBLtWJ30E3XtM7ydcQtDvgEJ5ypKi0N9P1Xj8UzEcaTOraOAE6lcAJq
haL/eG+tiBOYpBSIvO2cvIBmrQKBgQDAC7F52CHeb09Rs+gr7jDoq9gqjO1ZXMOD
3JYHYcVG/puIOvdGZOQ/gm9GEfvfnN09oALX6478pbpqBS5Yk3icVWsLPaokcn9N
UR5k5Ms9Hug4R25UFdkDvFnkKGSdoEmwoKn4QBKPZpSQJ2pTxhyX5w6UP/gL6ROq
u0Ro95OmPQKBgBtXJdd9DuG8f7ilQIEyVLWcxYYKQNX08WiIpffs4phJbj5QG3MG
W+D+1DIi+9g8cPz6KuHp1UcbfzavYtjCEDuH8wrGv5dY7g6h17EZRIfoz/GBiEPp
eHcea3Lyn6SdWxj67aEQxjSpE7/dGmUJpURsPITx6CaKZSe6DC6WeaSBAoGBALL/
8ysrfd4TB+6SbpvLxsCHs9NtSalaYk4co6Y7xiI3HIbs1yBA19IuZEL+bjLtxfUz
mJLi14K7gjZhn+IlimzE3SI8FsMkCW3qZxcJfjn4/d+/DKHJP15RB8Q2thmJlkXQ
aryeE+6fYWe/pUZySKJ5Vchum2eWlqMzKz9fS7rNAoGAEfjHvgt9VuZUc9NqGyYD
PT7/T0JJl9dIuwu7gcjlXTV97lWn7enT0Cjp83co0fvn/GpMvAS5oerj3CNSKxjB
98vsYZmUESOj+slMnIJXQyLu76JYyVZ/JvuGmGNWaFPbet3S0NLpSIQ8agswQKH0
6l0XvY89DsHtR6SPMTVyLf0=
-----END PRIVATE KEY-----`;

function stubFetch(handler) {
  const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    return handler(url, init);
  };
  return () => {
    globalThis.fetch = real;
  };
}

test('MailChannels error handling and options', async (t) => {
  assert.throws(
    () => createMailchannelsSender({ email: { mailchannelsEndpoint: 'https://api.mailchannels.net/tx/v1/send' } }),
    /EMAIL_FROM is not set/,
  );

  const config = configWith({
    EMAIL_PROVIDER: 'mailchannels',
    EMAIL_FROM: 'Sign in <from@example.com>',
    EMAIL_REPLY_TO: 'reply@example.com',
  });

  // Rejection by MailChannels (lines 33-35)
  const restore1 = stubFetch(async () => new Response('Invalid recipient', { status: 400 }));
  t.after(restore1);

  const sender = createMailchannelsSender(config);
  await assert.rejects(
    () => sender.send({ to: 'to@example.com', subject: 'Code', text: 'txt', html: '<p>html</p>' }),
    /MailChannels rejected the message \(HTTP 400\): Invalid recipient/,
  );

  // Rejection with unreadable body
  const restore2 = stubFetch(async () => ({
    ok: false,
    status: 500,
    text: () => Promise.reject(new Error('stream error')),
  }));
  t.after(restore2);

  await assert.rejects(
    () => sender.send({ to: 'to@example.com', subject: 'Code', text: 'txt', html: '<p>html</p>' }),
    /MailChannels rejected the message \(HTTP 500\):/,
  );

  // Success with custom msg.from and msg.replyTo
  let capturedBody;
  const restore3 = stubFetch(async (url, init) => {
    capturedBody = JSON.parse(init.body);
    return new Response('{}', { status: 200 });
  });
  t.after(restore3);

  const res = await sender.send({
    to: 'to@example.com',
    from: 'Custom <custom@example.com>',
    replyTo: 'custom-reply@example.com',
    subject: 'Code',
    text: 'txt',
    html: '<p>html</p>',
  });
  assert.equal(res.delivered, true);
  assert.equal(capturedBody.from.email, 'custom@example.com');
  assert.equal(capturedBody.from.name, 'Custom');
  assert.equal(capturedBody.reply_to.email, 'custom-reply@example.com');
});

test('Notify error handling and options', async (t) => {
  assert.throws(
    () => createNotifySender({ email: { notifyApiKey: '', notifyTemplateId: 't1' } }),
    /NOTIFY_API_KEY is not set/,
  );
  assert.throws(
    () => createNotifySender({ email: { notifyApiKey: 'sag-live-11111111-2222-3333-4444-555555555555-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' } }),
    /NOTIFY_TEMPLATE_ID is not set/,
  );

  const serviceId = '11111111-2222-3333-4444-555555555555';
  const secret = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const config = configWith({
    EMAIL_PROVIDER: 'notify',
    EMAIL_FROM: 'no-reply@example.com',
    NOTIFY_API_KEY: 'sag-live-' + serviceId + '-' + secret,
    NOTIFY_TEMPLATE_ID: 'template-1',
  });

  // Rejection by Notify (lines 59-61)
  const restore1 = stubFetch(async () => new Response('Template not found', { status: 400 }));
  t.after(restore1);

  const sender = createNotifySender(config);
  await assert.rejects(
    () => sender.send({ to: 'to@example.com', code: '123456', ttlMinutes: 10 }),
    /Notify rejected the message \(HTTP 400\): Template not found/,
  );

  // Success with personalisation and json parse fallback (line 62)
  const restore2 = stubFetch(async (url) => {
    assert.ok(url.endsWith('/v2/notifications/email'));
    return {
      ok: true,
      status: 200,
      json: () => Promise.reject(new Error('not json')),
    };
  });
  t.after(restore2);

  const res = await sender.send({
    to: 'to@example.com',
    code: '123456',
    ttlMinutes: 10,
    personalisation: { extra: 'param' },
  });
  assert.equal(res.delivered, true);
  assert.equal(res.id, undefined);
});

test('SES error handling and options', async (t) => {
  assert.throws(
    () => createSesSender(configWith({ EMAIL_PROVIDER: 'ses', SES_REGION: 'eu-west-1' }), {}),
    /EMAIL_FROM is not set/,
  );

  const config = configWith({
    EMAIL_PROVIDER: 'ses',
    EMAIL_FROM: 'no-reply@example.com',
    SES_REGION: 'eu-west-1',
    EMAIL_REPLY_TO: 'reply@example.com',
  });

  // Rejection by SES (lines 55-57)
  const restore1 = stubFetch(async () => new Response('Configuration set does not exist', { status: 400 }));
  t.after(restore1);

  const sender = createSesSender(config, {
    AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'secret',
  });
  await assert.rejects(
    () => sender.send({ to: 'to@example.com', subject: 'Sub', text: 'txt', html: '<p>html</p>' }),
    /SES rejected the message \(HTTP 400\): Configuration set does not exist/,
  );

  // Success with custom msg.from, msg.replyTo, and fallback for json (lines 34-35, 58)
  let capturedBody;
  const restore2 = stubFetch(async (url, init) => {
    capturedBody = JSON.parse(init.body);
    return {
      ok: true,
      status: 200,
      json: () => Promise.reject(new Error('no json')),
    };
  });
  t.after(restore2);

  const res = await sender.send({
    to: 'to@example.com',
    from: 'Custom <custom@example.com>',
    replyTo: 'custom-reply@example.com',
    subject: 'Sub',
    text: 'txt',
    html: '<p>html</p>',
  });
  assert.equal(res.delivered, true);
  assert.equal(res.id, undefined);
  assert.equal(capturedBody.FromEmailAddress, 'Custom <custom@example.com>');
  assert.deepEqual(capturedBody.ReplyToAddresses, ['custom-reply@example.com']);
});

test('Cloudflare sender checks environment and throws outside Worker', async () => {
  const config = configWith({
    EMAIL_PROVIDER: 'cloudflare',
    EMAIL_FROM: 'no-reply@example.com',
  });

  assert.throws(
    () => createCloudflareSender(config, {}),
    /no send_email binding is bound/,
  );

  assert.throws(
    () => createCloudflareSender({ email: { cloudflareBindingName: 'SE' } }, { SE: { send: () => {} } }),
    /EMAIL_FROM is not set/,
  );

  const fakeBinding = { send: async () => {} };
  const sender = createCloudflareSender(config, { SEND_EMAIL: fakeBinding });
  assert.equal(sender.name, 'cloudflare');

  await assert.rejects(
    () => sender.send({ to: 'to@example.com', subject: 'Sub', text: 'txt', html: '<p>html</p>' }),
    /the cloudflare email sender only works inside a Cloudflare Worker/,
  );
});

test('createEmailSender and isConsoleSender helper', async () => {
  assert.equal(isConsoleSender({ email: { provider: 'console' } }), true);
  assert.equal(isConsoleSender({ email: { provider: 'ses' } }), false);

  const ses = await createEmailSender(
    configWith({ EMAIL_PROVIDER: 'ses', SES_REGION: 'us-east-1', EMAIL_FROM: 'a@b.c' }),
    { AWS_ACCESS_KEY_ID: 'k', AWS_SECRET_ACCESS_KEY: 's' },
  );
  assert.equal(ses.name, 'ses');

  const notify = await createEmailSender(
    configWith({
      EMAIL_PROVIDER: 'notify',
      EMAIL_FROM: 'a@b.c',
      NOTIFY_API_KEY: 'sag-live-11111111-2222-3333-4444-555555555555-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      NOTIFY_TEMPLATE_ID: 't1',
    }),
    {},
  );
  assert.equal(notify.name, 'notify');

  const cloudflare = await createEmailSender(
    configWith({ EMAIL_PROVIDER: 'cloudflare', EMAIL_FROM: 'a@b.c' }),
    { SEND_EMAIL: { send: () => {} } },
  );
  assert.equal(cloudflare.name, 'cloudflare');

  const smtp = await createEmailSender(
    configWith({ EMAIL_PROVIDER: 'smtp', EMAIL_FROM: 'a@b.c', SMTP_URL: 'smtp://127.0.0.1:25' }),
    {},
  );
  assert.equal(smtp.name, 'smtp');
});

test('message and mime helpers cover organisation and reply-to', () => {
  const msg = otpMessage({
    code: '123456',
    ttlMinutes: 5,
    organisation: 'Acme Corp',
    issuerHost: 'id.example.com',
  });
  assert.match(msg.text, /Sent by Acme Corp \(id\.example\.com\)\./);

  const mime = buildMimeMessage({
    to: 'to@example.com',
    from: 'from@example.com',
    replyTo: 'reply@example.com',
    subject: 'Subject',
    text: 'Body',
    html: '<p>Body</p>',
  });
  assert.match(mime, /\r\nReply-To: reply@example\.com\r\n/);

  assert.equal(formatAddress({ name: '', address: 'a@b.c' }), 'a@b.c');
  assert.equal(formatAddress({ name: 'Hello "World"', address: 'a@b.c' }), '"Hello World" <a@b.c>');
});

test('SMTP sender delivery without TLS and with AUTH LOGIN', async (t) => {
  assert.throws(
    () => createSmtpSender({ email: { smtpUrl: '', from: 'a@b.c' } }),
    /SMTP_URL is not set/,
  );
  assert.throws(
    () => createSmtpSender({ email: { smtpUrl: 'smtp://localhost', from: '' } }),
    /EMAIL_FROM is not set/,
  );

  const received = [];
  const server = createServer((socket) => {
    socket.write('220 relay.test ESMTP\r\n');
    let buffer = '';
    let inData = false;
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      while (buffer.includes('\r\n')) {
        const end = buffer.indexOf('\r\n');
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (inData) {
          received.push(line);
          if (line === '.') {
            inData = false;
            socket.write('250 2.0.0 OK queued\r\n');
          }
          continue;
        }
        received.push(line);
        if (line.startsWith('EHLO ')) socket.write('250-relay.test\r\n250 AUTH LOGIN\r\n');
        else if (line === 'AUTH LOGIN') socket.write('334 VXNlcm5hbWU6\r\n');
        else if (line === Buffer.from('myuser').toString('base64')) socket.write('334 UGFzc3dvcmQ6\r\n');
        else if (line === Buffer.from('mypass').toString('base64')) socket.write('235 2.7.0 Authenticated\r\n');
        else if (line.startsWith('MAIL FROM:') || line.startsWith('RCPT TO:')) socket.write('250 2.1.0 OK\r\n');
        else if (line === 'DATA') {
          inData = true;
          socket.write('354 Start mail input\r\n');
        } else if (line === 'QUIT') socket.write('221 2.0.0 Bye\r\n');
      }
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;

  const config = configWith({
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM: 'Sign in <sender@example.com>',
    SMTP_URL: `smtp://myuser:mypass@127.0.0.1:${port}?starttls=false`,
  });

  const sender = createSmtpSender(config);
  const result = await sender.send({
    to: 'recipient@example.com',
    subject: 'Test Subject',
    text: 'Hello\n.world\n',
    html: '<p>Hello\n.world</p>',
  });
  assert.equal(result.delivered, true);
  assert.ok(received.includes('AUTH LOGIN'));
  assert.ok(received.includes('MAIL FROM:<sender@example.com>'));
  assert.ok(received.includes('RCPT TO:<recipient@example.com>'));
  // Verify dot stuffing: '.world' became '..world' in data transmission
  assert.ok(received.some((l) => l.includes('..world')));
});

test('SMTP sender delivery with STARTTLS and AUTH PLAIN', async (t) => {
  const received = [];
  const server = createServer((socket) => {
    socket.write('220 relay.test ESMTP\r\n');
    let buffer = '';
    let inData = false;
    let isTls = false;

    const setupListener = (s) => {
      s.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        while (buffer.includes('\r\n')) {
          const end = buffer.indexOf('\r\n');
          const line = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          if (inData) {
            received.push(line);
            if (line === '.') {
              inData = false;
              s.write('250 2.0.0 OK queued\r\n');
            }
            continue;
          }
          received.push(line);
          if (line.startsWith('EHLO ')) {
            if (!isTls) {
              s.write('250-relay.test\r\n250 STARTTLS\r\n');
            } else {
              s.write('250-relay.test\r\n250 AUTH PLAIN\r\n');
            }
          } else if (line === 'STARTTLS') {
            s.write('220 2.0.0 Ready to start TLS\r\n');
            isTls = true;
            const tlsSocket = new tls.TLSSocket(socket, {
              isServer: true,
              key: testKey,
              cert: testCert,
            });
            setupListener(tlsSocket);
          } else if (line.startsWith('AUTH PLAIN ')) {
            s.write('235 2.7.0 Authentication successful\r\n');
          } else if (line.startsWith('MAIL FROM:') || line.startsWith('RCPT TO:')) {
            s.write('250 2.1.0 OK\r\n');
          } else if (line === 'DATA') {
            inData = true;
            s.write('354 End data with <CR><LF>.<CR><LF>\r\n');
          } else if (line === 'QUIT') {
            s.write('221 2.0.0 Bye\r\n');
          }
        }
      });
    };

    setupListener(socket);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;

  const config = configWith({
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM: 'sender@example.com',
    SMTP_URL: `smtp://alice:secret@127.0.0.1:${port}?insecure=true`,
  });

  const sender = createSmtpSender(config);
  const result = await sender.send({
    to: 'bob@example.com',
    subject: 'Hello',
    text: 'Plain',
    html: '<p>HTML</p>',
  });
  assert.equal(result.delivered, true);
  assert.ok(received.includes('STARTTLS'));
  assert.ok(received.some((l) => l.startsWith('AUTH PLAIN ')));
});

test('SMTP sender delivery with smtps:// (implicit TLS)', async (t) => {
  const server = tls.createServer({ key: testKey, cert: testCert }, (socket) => {
    socket.write('220 relay.test ESMTP\r\n');
    let buffer = '';
    let inData = false;
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      while (buffer.includes('\r\n')) {
        const end = buffer.indexOf('\r\n');
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (inData) {
          if (line === '.') {
            inData = false;
            socket.write('250 queued\r\n');
          }
          continue;
        }
        if (line.startsWith('EHLO ')) socket.write('250-relay.test\r\n250 AUTH PLAIN\r\n');
        else if (line.startsWith('AUTH PLAIN ')) socket.write('235 authenticated\r\n');
        else if (line.startsWith('MAIL FROM:') || line.startsWith('RCPT TO:')) socket.write('250 ok\r\n');
        else if (line === 'DATA') {
          inData = true;
          socket.write('354 send it\r\n');
        } else if (line === 'QUIT') socket.write('221 bye\r\n');
      }
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;

  const config = configWith({
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM: 'sender@example.com',
    SMTP_URL: `smtps://alice:secret@127.0.0.1:${port}?insecure=true`,
  });

  const sender = createSmtpSender(config);
  const result = await sender.send({
    to: 'bob@example.com',
    subject: 'Hello',
    text: 'Plain',
    html: '<p>HTML</p>',
  });
  assert.equal(result.delivered, true);
});

test('SMTP sender handles unsupported auth method and unexpected status replies', async (t) => {
  // Unsupported AUTH method
  const server1 = createServer((socket) => {
    socket.write('220 relay.test ESMTP\r\n');
    socket.on('data', (chunk) => {
      if (chunk.toString().startsWith('EHLO')) {
        socket.write('250-relay.test\r\n250 AUTH GSSAPI\r\n');
      }
    });
  });
  await new Promise((resolve) => server1.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server1.close(resolve)));
  const port1 = server1.address().port;

  const sender1 = createSmtpSender(configWith({
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM: 'a@b.c',
    SMTP_URL: `smtp://alice:secret@127.0.0.1:${port1}?starttls=false`,
  }));
  await assert.rejects(
    () => sender1.send({ to: 'to@example.com', subject: 's', text: 't', html: '<p>t</p>' }),
    /the relay advertises no authentication method this sender supports/,
  );

  // Unexpected response status code (line 145)
  const server2 = createServer((socket) => {
    socket.write('220 relay.test ESMTP\r\n');
    socket.on('data', (chunk) => {
      if (chunk.toString().startsWith('EHLO')) {
        socket.write('500 Command not recognized\r\n');
      }
    });
  });
  await new Promise((resolve) => server2.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server2.close(resolve)));
  const port2 = server2.address().port;

  const sender2 = createSmtpSender(configWith({
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM: 'a@b.c',
    SMTP_URL: `smtp://127.0.0.1:${port2}?starttls=false`,
  }));
  await assert.rejects(
    () => sender2.send({ to: 'to@example.com', subject: 's', text: 't', html: '<p>t</p>' }),
    /SMTP relay replied 500 where 250 was expected/,
  );
});

test('SMTP sender handles socket error and TLS rejection', async (t) => {
  // Socket error while waiting for reply (lines 130-134, 155-156)
  const sockets1 = new Set();
  const server1 = createServer((socket) => {
    sockets1.add(socket);
    socket.on('close', () => sockets1.delete(socket));
    socket.on('error', () => {});
    socket.write('220 relay.test ESMTP\r\n');
    socket.on('data', () => {
      socket.resetAndDestroy();
    });
  });
  await new Promise((resolve) => server1.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    for (const s of sockets1) s.destroy();
    return new Promise((resolve) => server1.close(resolve));
  });
  const port1 = server1.address().port;

  const sender1 = createSmtpSender(configWith({
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM: 'a@b.c',
    SMTP_URL: `smtp://127.0.0.1:${port1}?starttls=false`,
  }));
  await assert.rejects(
    () => sender1.send({ to: 'to@example.com', subject: 's', text: 't', html: '<p>t</p>' }),
  );

  // TLS error during secured() (rejectUnauthorized: true against self-signed cert, lines 185)
  const sockets2 = new Set();
  const server2 = tls.createServer({ key: testKey, cert: testCert }, (socket) => {
    sockets2.add(socket);
    socket.on('close', () => sockets2.delete(socket));
    socket.on('error', () => {});
    socket.write('220 relay.test ESMTP\r\n');
  });
  server2.on('tlsClientError', (err, socket) => {
    socket.destroy();
  });
  server2.on('connection', (socket) => {
    sockets2.add(socket);
    socket.on('close', () => sockets2.delete(socket));
  });
  await new Promise((resolve) => server2.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    for (const s of sockets2) s.destroy();
    return new Promise((resolve) => server2.close(resolve));
  });
  const port2 = server2.address().port;

  const sender2 = createSmtpSender(configWith({
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM: 'a@b.c',
    SMTP_URL: `smtps://127.0.0.1:${port2}`,
  }));
  await assert.rejects(
    () => sender2.send({ to: 'to@example.com', subject: 's', text: 't', html: '<p>t</p>' }),
  );
});
