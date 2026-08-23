// AWS Simple Email Service, via the v2 API.
//
// SigV4 signing is done by src/crypto/sigv4.js rather than the AWS SDK, so
// this works unchanged on Workers as well as Lambda and adds nothing to the
// bundle. On Lambda the credentials come from the execution role through the
// environment, so nothing needs configuring beyond the region.

import { fetchWithTimeout } from '../util/http.js';
import { signRequest, credentialsFromEnv } from '../crypto/sigv4.js';

export function createSesSender(config, env) {
  const region = config.email.sesRegion;
  if (!region) throw new Error('EMAIL_PROVIDER is ses but neither SES_REGION nor AWS_REGION is set');
  if (!config.email.from) throw new Error('EMAIL_PROVIDER is ses but EMAIL_FROM is not set');
  const endpoint = 'https://email.' + region + '.amazonaws.com/v2/email/outbound-emails';

  return {
    name: 'ses',
    async send(msg) {
      const payload = {
        FromEmailAddress: msg.from || config.email.from,
        Destination: { ToAddresses: [msg.to] },
        Content: {
          Simple: {
            Subject: { Data: msg.subject, Charset: 'UTF-8' },
            Body: {
              Text: { Data: msg.text, Charset: 'UTF-8' },
              Html: { Data: msg.html, Charset: 'UTF-8' },
            },
          },
        },
      };
      if (msg.replyTo || config.email.replyTo) {
        payload.ReplyToAddresses = [msg.replyTo || config.email.replyTo];
      }
      // A configuration set is how SES reports bounces and complaints, which an
      // operator needs in order to keep their sending reputation.
      if (config.email.sesConfigurationSet) {
        payload.ConfigurationSetName = config.email.sesConfigurationSet;
      }

      const body = JSON.stringify(payload);
      const headers = await signRequest({
        method: 'POST',
        url: endpoint,
        body,
        service: 'ses',
        region,
        credentials: credentialsFromEnv(env ?? {}),
        headers: { 'content-type': 'application/json' },
      });

      const res = await fetchWithTimeout(endpoint, { method: 'POST', headers, body }, 8000);
      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        throw new Error('SES rejected the message (HTTP ' + res.status + '): ' + detail.slice(0, 300));
      }
      const out = await res.json().catch(() => ({}));
      return { delivered: true, id: out.MessageId };
    },
  };
}
