// GOV.UK Notify.
//
// Notify owns the template, so SAG sends personalisation rather than a body:
// the operator creates a template containing ((code)) and ((ttl_minutes)) and
// supplies its id. That is the point of Notify - the words are managed by the
// service team, in their own tone, with their own accessibility review.

import { fetchWithTimeout } from '../util/http.js';
import { signHs256 } from '../crypto/jose.js';
import { nowSeconds } from '../util/bytes.js';

/**
 * A Notify API key is "<name>-<service id>-<secret>", where both the service
 * id and the secret are 36 character UUIDs. The JWT is signed with the secret
 * and carries the service id as its issuer.
 */
export function parseNotifyKey(apiKey) {
  const key = String(apiKey || '').trim();
  if (key.length < 73) throw new Error('NOTIFY_API_KEY is too short to be a Notify key');
  const secret = key.slice(-36);
  const serviceId = key.slice(-73, -37);
  if (!/^[0-9a-f-]{36}$/i.test(secret) || !/^[0-9a-f-]{36}$/i.test(serviceId)) {
    throw new Error('NOTIFY_API_KEY is not in the expected <name>-<service id>-<secret> form');
  }
  return { serviceId, secret };
}

export function createNotifySender(config) {
  const { notifyApiKey, notifyTemplateId, notifyBaseUrl } = config.email;
  if (!notifyApiKey) throw new Error('EMAIL_PROVIDER is notify but NOTIFY_API_KEY is not set');
  if (!notifyTemplateId) throw new Error('EMAIL_PROVIDER is notify but NOTIFY_TEMPLATE_ID is not set');
  const { serviceId, secret } = parseNotifyKey(notifyApiKey);

  return {
    name: 'notify',
    async send(msg) {
      // Notify authenticates each request with a short-lived JWT rather than a
      // bearer key, so a captured request is only replayable for 30 seconds.
      const token = await signHs256(secret, { iss: serviceId, iat: nowSeconds() });
      const body = JSON.stringify({
        email_address: msg.to,
        template_id: notifyTemplateId,
        personalisation: {
          code: msg.code,
          ttl_minutes: msg.ttlMinutes,
          ...msg.personalisation,
        },
      });
      const res = await fetchWithTimeout(
        notifyBaseUrl.replace(/\/+$/, '') + '/v2/notifications/email',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
          body,
        },
        8000,
      );
      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        throw new Error('Notify rejected the message (HTTP ' + res.status + '): ' + detail.slice(0, 300));
      }
      const out = await res.json().catch(() => ({}));
      return { delivered: true, id: out.id };
    },
  };
}
