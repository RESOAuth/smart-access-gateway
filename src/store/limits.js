// Rate limits for the one route that costs the operator money.
//
// Email OTP sends mail on request, so without a limit anybody can make a
// deployment send thousands of messages to addresses that never asked for
// them. The counters cannot live in the sealed transaction, because the
// person holding it can simply present an older copy, so they live in the
// shared state store when one is configured.
//
// Two limits, both per address: a few sends per window, and a daily ceiling.
// The address is never stored - the key is an HMAC of it under the master
// secret, so a store dump is not a mailing list.
//
// When no store is configured nothing is enforced, and that is deliberate: a
// platform rate limiting rule in front of the deployment is the recommended
// control (see docs/state-and-limits.md). Start-up says so, in the banner and
// in the log; /healthz does not, because which defences are absent is not a
// thing to publish to strangers.

import { derive, hmac } from '../crypto/secrets.js';
import { stripPlusTag } from '../identity.js';
import { b64u, nowSeconds } from '../util/bytes.js';

const DAY = 86400;

/** A stable, non-reversible key for an address. */
async function addressKey(config, email) {
  const key = await derive(config.secrets[0], 'rate-limit', 32);
  // Always the untagged address, whatever SANITISE_PLUS_EMAILS says. Identity
  // is a policy an operator can set; a mailbox is a fact, and keying on the
  // tag would let one person walk past the limit by inventing a new one on
  // every attempt.
  const mailbox = stripPlusTag(String(email).toLowerCase());
  return b64u(await hmac(key, mailbox)).slice(0, 22);
}

/**
 * May a code be sent to this address now?
 *
 * @returns {Promise<{allowed: boolean, enforced: boolean, reason?: string,
 *   retryAfterSeconds?: number}>}
 */
export async function checkOtpSendAllowed(ctx, email) {
  const { config, stateStore } = ctx;
  const { sendWindowSeconds, sendBurst, sendDailyLimit } = config.otp;
  const windowed = sendWindowSeconds > 0 && sendBurst > 0;
  if (!stateStore || (!windowed && sendDailyLimit === 0)) {
    return { allowed: true, enforced: false };
  }

  const tag = await addressKey(config, email);
  const now = nowSeconds();
  try {
    if (windowed) {
      // A fixed window rather than one claim per send, for two reasons: the
      // person can be told exactly how long is left rather than the worst
      // case, and a small burst means somebody whose first code went to spam
      // can ask again instead of waiting out the whole window for a message
      // that never arrived.
      const bucket = Math.floor(now / sendWindowSeconds);
      const used = await stateStore.increment('otp-send:' + tag + ':' + bucket, sendWindowSeconds);
      if (used > sendBurst) {
        return {
          allowed: false,
          enforced: true,
          reason: 'window',
          retryAfterSeconds: (bucket + 1) * sendWindowSeconds - now,
        };
      }
    }
    if (sendDailyLimit > 0) {
      // A fixed daily bucket rather than a rolling day, because a rolling
      // window needs a list of timestamps and this needs one integer.
      const bucket = Math.floor(now / DAY);
      const used = await stateStore.increment('otp-day:' + tag + ':' + bucket, DAY);
      if (used > sendDailyLimit) {
        return {
          allowed: false,
          enforced: true,
          reason: 'daily',
          retryAfterSeconds: (bucket + 1) * DAY - now,
        };
      }
    }
  } catch (err) {
    // Unlike single-use codes, this control protects the operator's mail bill
    // rather than somebody's account, so a store outage must not lock every
    // person out of signing in. Fail open, loudly.
    ctx.log.error('otp rate limit check failed; allowing the send', { error: err.message });
    return { allowed: true, enforced: false, degraded: true };
  }
  return { allowed: true, enforced: true };
}
