// Email delivery.
//
// Every sender exposes the same one method, so the OTP flow never knows which
// is in play. Providers that need a network call use fetchWithTimeout, because
// a hung mail API must not hold a Worker or Lambda invocation open.

import { createConsoleSender } from './console.js';

const FACTORIES = {
  console: createConsoleSender,
};

/**
 * Lazily loaded senders. Keeping these out of the static import graph means a
 * Workers bundle does not carry the AWS signing code unless SES is configured.
 */
const LAZY = {
  ses: () => import('./ses.js').then((m) => m.createSesSender),
  notify: () => import('./notify.js').then((m) => m.createNotifySender),
  mailchannels: () => import('./mailchannels.js').then((m) => m.createMailchannelsSender),
  cloudflare: () => import('./cloudflare.js').then((m) => m.createCloudflareSender),
  smtp: () => import('./smtp.js').then((m) => m.createSmtpSender),
};

/**
 * Build the configured sender.
 *
 * @returns {Promise<{name: string, send(msg): Promise<object>}>}
 */
export async function createEmailSender(config, env = {}) {
  const name = config.email.provider;
  // eslint-disable-next-line security/detect-object-injection -- lookup of configured email provider in fixed registries
  const factory = FACTORIES[name] ?? (LAZY[name] ? await LAZY[name]() : undefined);
  if (!factory) throw new Error('unknown EMAIL_PROVIDER: ' + name);
  return factory(config, env);
}

/** True when the operator has accepted that codes only reach the log. */
export const isConsoleSender = (config) => config.email.provider === 'console';
