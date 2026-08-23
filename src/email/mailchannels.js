// MailChannels, which is the usual way to send mail from a Cloudflare Worker.

import { fetchWithTimeout } from '../util/http.js';
import { parseAddress } from './mime.js';

export function createMailchannelsSender(config) {
  const { mailchannelsEndpoint, mailchannelsApiKey } = config.email;
  if (!config.email.from) throw new Error('EMAIL_PROVIDER is mailchannels but EMAIL_FROM is not set');

  return {
    name: 'mailchannels',
    async send(msg) {
      const from = parseAddress(msg.from || config.email.from);
      const body = JSON.stringify({
        personalizations: [{ to: [{ email: msg.to }] }],
        from: { email: from.address, name: from.name },
        subject: msg.subject,
        content: [
          // Order matters: a client picks the last part it understands, so the
          // plain text alternative has to come first.
          { type: 'text/plain', value: msg.text },
          { type: 'text/html', value: msg.html },
        ],
        ...(msg.replyTo || config.email.replyTo
          ? { reply_to: { email: parseAddress(msg.replyTo || config.email.replyTo).address } }
          : {}),
      });
      const headers = { 'content-type': 'application/json' };
      if (mailchannelsApiKey) headers['x-api-key'] = mailchannelsApiKey;

      const res = await fetchWithTimeout(mailchannelsEndpoint, { method: 'POST', headers, body }, 8000);
      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        throw new Error('MailChannels rejected the message (HTTP ' + res.status + '): ' + detail.slice(0, 300));
      }
      return { delivered: true };
    },
  };
}
