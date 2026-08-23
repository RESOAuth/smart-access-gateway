// SMTP.
//
// This one needs raw TCP, which Workers do not offer, so it only works on Node
// and on Lambda. It is included because plenty of organisations are required
// to send through a particular relay, and because it makes local testing
// against a container such as Mailpit possible.
//
// Only what is needed to hand one message to a relay is implemented: EHLO,
// optional STARTTLS, optional AUTH PLAIN or LOGIN, then MAIL, RCPT and DATA.

import { buildMimeMessage, parseAddress } from './mime.js';
import { b64Text } from '../util/bytes.js';

const NUL = String.fromCharCode(0);

/** Parse smtp://user:pass@host:port or smtps://... */
export function parseSmtpUrl(input) {
  const url = new URL(input);
  if (url.protocol !== 'smtp:' && url.protocol !== 'smtps:') {
    throw new Error('SMTP_URL must start with smtp:// or smtps://');
  }
  const secure = url.protocol === 'smtps:';
  return {
    host: url.hostname,
    port: Number(url.port) || (secure ? 465 : 587),
    secure,
    username: url.username ? decodeURIComponent(url.username) : undefined,
    password: url.password ? decodeURIComponent(url.password) : undefined,
    // A local relay usually has a self-signed certificate. Requiring a valid
    // one by default and allowing it to be waived explicitly is safer than the
    // other way round.
    rejectUnauthorized: url.searchParams.get('insecure') !== 'true',
    requireTls: url.searchParams.get('starttls') !== 'false',
  };
}

export function createSmtpSender(config) {
  if (!config.email.smtpUrl) throw new Error('EMAIL_PROVIDER is smtp but SMTP_URL is not set');
  if (!config.email.from) throw new Error('EMAIL_PROVIDER is smtp but EMAIL_FROM is not set');
  const options = parseSmtpUrl(config.email.smtpUrl);

  return {
    name: 'smtp',
    async send(msg) {
      const from = parseAddress(msg.from || config.email.from);
      const raw = buildMimeMessage({ ...msg, from: msg.from || config.email.from });
      await deliver(options, { from: from.address, to: parseAddress(msg.to).address, raw });
      return { delivered: true };
    },
  };
}

/** One conversation with a relay. */
async function deliver(options, { from, to, raw }) {
  const net = await import('node:net');
  const tls = await import('node:tls');

  let socket = options.secure
    ? tls.connect({ host: options.host, port: options.port, rejectUnauthorized: options.rejectUnauthorized })
    : net.createConnection({ host: options.host, port: options.port });

  const session = createSession(socket);
  try {
    await session.expect(220);
    let capabilities = await session.command('EHLO ' + hostnameFor(from), 250);

    if (!options.secure && options.requireTls && /STARTTLS/i.test(capabilities)) {
      await session.command('STARTTLS', 220);
      socket = tls.connect({
        socket,
        servername: options.host,
        rejectUnauthorized: options.rejectUnauthorized,
      });
      session.rebind(socket);
      await session.secured();
      // Capabilities have to be read again: a relay usually only advertises
      // AUTH once the connection is encrypted.
      capabilities = await session.command('EHLO ' + hostnameFor(from), 250);
    }

    if (options.username) {
      if (/AUTH[ =-][^\r\n]*PLAIN/i.test(capabilities)) {
        await session.command('AUTH PLAIN ' + b64Text(NUL + options.username + NUL + options.password), 235);
      } else if (/AUTH[ =-][^\r\n]*LOGIN/i.test(capabilities)) {
        await session.command('AUTH LOGIN', 334);
        await session.command(b64Text(options.username), 334);
        await session.command(b64Text(options.password), 235);
      } else {
        throw new Error('the relay advertises no authentication method this sender supports');
      }
    }

    await session.command('MAIL FROM:<' + from + '>', 250);
    await session.command('RCPT TO:<' + to + '>', 250);
    await session.command('DATA', 354);
    // Dot-stuffing: a body line that is a single dot would otherwise be read
    // as the end of the message.
    await session.command(raw.replace(/\r\n\./g, '\r\n..') + '\r\n.', 250);
    await session.command('QUIT', 221).catch(() => {});
  } finally {
    session.close();
  }
}

const hostnameFor = (address) => address.split('@')[1] || 'localhost';

/**
 * A very small line-oriented SMTP client.
 *
 * A reply can span several lines, each marked by a hyphen after the status
 * code, and is only complete once a line arrives with a space there instead.
 */
function createSession(initialSocket) {
  let socket = initialSocket;
  let buffer = '';
  let waiter;
  let failure;

  const onData = (chunk) => {
    buffer += chunk.toString('utf8');
    flush();
  };

  const flush = () => {
    if (!waiter) return;
    if (failure) {
      const { reject } = waiter;
      waiter = undefined;
      reject(failure);
      return;
    }
    // The final line of a reply looks like "250 text", as opposed to the
    // continuation form "250-text".
    const final = buffer.match(/^(\d{3}) [^\r\n]*\r\n/m);
    if (!final) return;
    const text = buffer;
    buffer = '';
    const code = Number(final[1]);
    const { resolve, reject, expected } = waiter;
    waiter = undefined;
    if (expected !== undefined && code !== expected) {
      reject(new Error('SMTP relay replied ' + code + ' where ' + expected + ' was expected: ' + text.trim()));
    } else {
      resolve(text);
    }
  };

  const attach = (s) => {
    s.setTimeout(15000, () => s.destroy(new Error('SMTP connection timed out')));
    s.on('data', onData);
    s.on('error', (err) => {
      failure = err;
      flush();
    });
  };
  attach(socket);

  const wait = (expected) =>
    new Promise((resolve, reject) => {
      waiter = { resolve, reject, expected };
      flush();
    });

  return {
    expect: wait,
    async command(line, expected) {
      socket.write(line + '\r\n');
      return wait(expected);
    },
    rebind(next) {
      socket.removeListener('data', onData);
      socket = next;
      buffer = '';
      failure = undefined;
      attach(socket);
    },
    /** Resolve once the TLS handshake has finished. */
    secured() {
      return new Promise((resolve, reject) => {
        if (socket.encrypted) return resolve();
        socket.once('secureConnect', resolve);
        socket.once('error', reject);
      });
    },
    close() {
      try {
        socket.end();
      } catch {
        /* already gone */
      }
    },
  };
}
