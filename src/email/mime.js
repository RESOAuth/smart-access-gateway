// Building a raw MIME message.
//
// Two senders need one: SMTP, and Cloudflare's email binding. Both want a
// complete RFC 5322 message rather than fields, so this assembles a
// multipart/alternative with a plain text part and an HTML part.
//
// Everything is quoted-printable rather than base64. A sign-in code email is
// almost all ASCII, so quoted-printable keeps it readable in a raw log, which
// matters when somebody is debugging why mail is not arriving.

import { b64, utf8 } from '../util/bytes.js';

/** RFC 2047 encoded-word, for a subject or display name with non-ASCII. */
export function encodeHeaderValue(value) {
  const s = String(value);
   
  if (/^[\x20-\x7e]*$/.test(s)) return s;
  return '=?UTF-8?B?' + b64(utf8(s)) + '?=';
}

/**
 * Quoted-printable, with soft line breaks at 76 characters.
 *
 * A trailing space or tab before a line break has to be encoded, otherwise
 * some relays strip it and the body no longer matches what was signed.
 */
export function quotedPrintable(input) {
  const bytes = utf8(String(input).replace(/\r?\n/g, '\r\n'));
  let out = '';
  let lineLength = 0;
  const push = (chunk) => {
    if (lineLength + chunk.length > 75) {
      out += '=\r\n';
      lineLength = 0;
    }
    out += chunk;
    lineLength += chunk.length;
  };
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte === 0x0d && bytes[i + 1] === 0x0a) {
      // Encode trailing whitespace before the break.
      if (out.endsWith(' ')) out = out.slice(0, -1) + '=20';
      else if (out.endsWith('\t')) out = out.slice(0, -1) + '=09';
      out += '\r\n';
      lineLength = 0;
      i++;
      continue;
    }
    if (byte === 0x3d || byte < 0x20 || byte > 0x7e) {
      push('=' + byte.toString(16).toUpperCase().padStart(2, '0'));
    } else {
      push(String.fromCharCode(byte));
    }
  }
  return out;
}

/** A message id that does not leak anything about the sender's internals. */
function messageId(fromDomain) {
  const random = crypto.getRandomValues(new Uint8Array(16));
  let hex = '';
  for (const b of random) hex += b.toString(16).padStart(2, '0');
  return '<' + hex + '@' + fromDomain + '>';
}

/** Split "Display Name <address@example.com>" into its parts. */
export function parseAddress(input) {
  const s = String(input || '').trim();
  const m = s.match(/^(.*?)\s*<([^>]+)>$/);
  if (m) return { name: m[1].replace(/^"|"$/g, '').trim() || undefined, address: m[2].trim() };
  return { address: s };
}

export function formatAddress({ name, address }) {
  if (!name) return address;
  return '"' + encodeHeaderValue(name).replaceAll('"', '') + '" <' + address + '>';
}

/**
 * Assemble the message.
 *
 * @param {object} msg {to, from, replyTo, subject, text, html, date}
 * @returns {string} A complete RFC 5322 message with CRLF line endings.
 */
export function buildMimeMessage(msg) {
  const from = parseAddress(msg.from);
  const to = parseAddress(msg.to);
  const domain = from.address.split('@')[1] || 'localhost';
  const boundary = 'sag-' + b64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^A-Za-z0-9]/g, '');

  const headers = [
    'From: ' + formatAddress(from),
    'To: ' + formatAddress(to),
    'Subject: ' + encodeHeaderValue(msg.subject),
    'Date: ' + (msg.date || new Date()).toUTCString().replace('GMT', '+0000'),
    'Message-ID: ' + messageId(domain),
    'MIME-Version: 1.0',
    // A one-time code is transactional and must never end up in a bulk folder
    // or be auto-replied to by an out-of-office responder.
    'Auto-Submitted: auto-generated',
    'X-Auto-Response-Suppress: All',
    'Content-Type: multipart/alternative; boundary="' + boundary + '"',
  ];
  if (msg.replyTo) headers.push('Reply-To: ' + formatAddress(parseAddress(msg.replyTo)));

  const parts = [
    '--' + boundary,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    quotedPrintable(msg.text),
    '--' + boundary,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    quotedPrintable(msg.html),
    '--' + boundary + '--',
    '',
  ];

  return headers.join('\r\n') + '\r\n\r\n' + parts.join('\r\n');
}
