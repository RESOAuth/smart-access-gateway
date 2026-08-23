// The one email SAG ever sends.
//
// It is deliberately plain. A sign-in code email that looks like marketing is
// both less trustworthy and more likely to be filtered, so there is no image,
// no tracking, and nothing to click - a code that must be typed back into the
// page the person already has open cannot be phished by forwarding the email.

import { escapeHtml } from '../util/http.js';
import { formatCodeForDisplay } from '../otp.js';

/**
 * @param {object} args
 * @param {string} args.code
 * @param {number} args.ttlMinutes
 * @param {string} [args.organisation]
 * @param {string} [args.clientName]  Which application asked
 * @param {string} args.issuerHost
 */
export function otpMessage(args) {
  const { code, ttlMinutes, organisation, clientName, issuerHost } = args;
  const shown = formatCodeForDisplay(code);
  const who = organisation ? organisation : issuerHost;
  const forApp = clientName ? ' to sign in to ' + clientName : '';

  const subject = 'Your sign-in code: ' + shown;

  const text = [
    'Your sign-in code is ' + shown,
    '',
    'Enter it on the page you already have open' + forApp + '. It expires in ' + ttlMinutes + ' minutes.',
    '',
    'If you did not try to sign in, you can ignore this email. Nobody can use',
    'this code without also having the sign-in page open on your device.',
    '',
    'Sent by ' + who + ' (' + issuerHost + ').',
  ].join('\n');

  const e = escapeHtml;
  const html = [
    '<!DOCTYPE html>',
    '<html lang="en-GB"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<title>' + e(subject) + '</title></head>',
    '<body style="margin:0;padding:24px;background:#f6f7f9;',
    'font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#16181d">',
    '<div style="max-width:480px;margin:0 auto;background:#fff;border:1px solid #d6dae1;',
    'border-radius:10px;padding:28px">',
    '<h1 style="margin:0 0 12px;font-size:20px">Your sign-in code</h1>',
    '<p style="margin:0 0 20px;color:#545a66">Enter this code on the page you already have open' +
      e(forApp) +
      '.</p>',
    '<p style="margin:0 0 20px;font:700 30px/1.2 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;',
    'letter-spacing:0.18em">' + e(shown) + '</p>',
    '<p style="margin:0 0 20px;color:#545a66">It expires in ' + ttlMinutes + ' minutes.</p>',
    '<p style="margin:0;color:#545a66;font-size:14px">If you did not try to sign in you can ignore ',
    'this email. Nobody can use this code without also having the sign-in page open on your device.</p>',
    '</div>',
    '<p style="max-width:480px;margin:12px auto 0;color:#545a66;font-size:13px">Sent by ' +
      e(who) +
      ' (' + e(issuerHost) + ').</p>',
    '</body></html>',
  ].join('');

  return { subject, text, html };
}
