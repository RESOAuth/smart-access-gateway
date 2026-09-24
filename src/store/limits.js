// Rate limits for mail delivery and local credential verification.
//
// Email OTP sends mail on request, so without a limit anybody can make a
// deployment send thousands of messages to addresses that never asked for
// them. The counters cannot live in the sealed transaction, because the
// person holding it can simply present an older copy, so they live in the
// shared state store when one is configured.
//
// OTP has two limits per address: a few sends per window, and a daily ceiling.
// Local authentication adds fail-closed address and optional network buckets.
// The address is never stored - the key is an HMAC of it under the master
// secret, so a store dump is not a mailing list or account list.
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

async function privateTag(config, purpose, value) {
  const key = await derive(config.secrets[0], 'rate-limit/' + purpose, 32);
  return b64u(await hmac(key, String(value))).slice(0, 22);
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

/**
 * Count local credential attempts by address and, when the adapter supplies
 * it, by network address. Unlike an email-send limit this protects an account,
 * so a missing or failed store denies the attempt rather than failing open.
 */
export async function checkLocalAuthAllowed(ctx, email, factor = 'password') {
  const { config, stateStore } = ctx;
  if (!stateStore) return { allowed: false, enforced: false, reason: 'store' };
  const window = config.localIdentities.attemptWindowSeconds;
  const bucket = Math.floor(nowSeconds() / window);
  try {
    // The Node adapter overwrites this header from the socket. It is never a
    // forwarded header supplied by the caller, so a password guesser cannot
    // choose a new value per request to walk around the network limit. Check
    // it first, so traffic already refused for one source cannot fill the
    // protected counter store with arbitrary address keys.
    const network = ctx.request.headers.get('x-sag-client-ip');
    if (network && config.localIdentities.networkMaxAttempts > 0) {
      const tag = await privateTag(config, 'network', network);
      const networkUsed = await stateStore.increment(
        'local-' + factor + ':network:' + tag + ':' + bucket,
        window,
        { failClosed: true },
      );
      if (networkUsed > config.localIdentities.networkMaxAttempts) {
        return { allowed: false, enforced: true, reason: 'limit' };
      }
    }
    const address = await addressKey(config, email);
    const used = await stateStore.increment(
      'local-' + factor + ':address:' + address + ':' + bucket,
      window,
      { failClosed: true },
    );
    const allowed = used <= config.localIdentities.maxAttempts;
    return { allowed, enforced: true, reason: allowed ? undefined : 'limit' };
  } catch (err) {
    ctx.log.error('local authentication rate limit failed; denying the attempt', { error: err.message });
    return { allowed: false, enforced: false, reason: 'store' };
  }
}
