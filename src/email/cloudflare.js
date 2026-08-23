// Cloudflare Email Routing, via a send_email binding.
//
// The binding takes a complete MIME message and will only send to an address
// that has been verified as a destination in the zone, so it is useful for
// routing codes to a fixed mailbox during a trial rather than for sending to
// arbitrary recipients. That restriction is Cloudflare's, not SAG's, and it is
// why CLOUDFLARE_EMAIL_DESTINATION exists.

import { buildMimeMessage, parseAddress } from './mime.js';

export function createCloudflareSender(config, env) {
  const binding = env?.[config.email.cloudflareBindingName];
  if (!binding || typeof binding.send !== 'function') {
    throw new Error(
      'EMAIL_PROVIDER is cloudflare but no send_email binding is bound as ' + config.email.cloudflareBindingName,
    );
  }
  if (!config.email.from) throw new Error('EMAIL_PROVIDER is cloudflare but EMAIL_FROM is not set');

  return {
    name: 'cloudflare',
    async send(msg) {
      // Email Routing can only deliver to a verified destination address. When
      // one is configured every code goes there instead of to the person,
      // which is a deliberate trial-only mode rather than a silent
      // misdelivery, so the caller is told it happened.
      const to = config.email.cloudflareDestination || msg.to;
      const from = parseAddress(msg.from || config.email.from).address;
      const raw = buildMimeMessage({ ...msg, to, from: msg.from || config.email.from });

      let EmailMessage;
      try {
        ({ EmailMessage } = await import('cloudflare:email'));
      } catch (cause) {
        throw new Error('the cloudflare email sender only works inside a Cloudflare Worker', { cause });
      }
      await binding.send(new EmailMessage(from, to, raw));
      return { delivered: true, redirected: to === msg.to ? undefined : to };
    },
  };
}
