// Operator-provisioned local identities.
//
// The core owns the schema, routing policy, sealing and authentication rules.
// The Node adapter owns the filesystem and Argon2 implementation, handed in as
// a binding so importing this module remains safe on Workers and Lambda.

import { derive, hmac, seal, unseal, SealError } from '../crypto/secrets.js';
import { normaliseEmail, domainOf } from '../identity.js';
import { b64u, randomToken, toHex, utf8 } from '../util/bytes.js';
import { relayedClaims } from '../profile.js';
import { PROFILE_CLAIMS } from '../config.js';
import { decodeBase32, encodeBase32, verifyTotp } from './totp.js';

const RECORD_VERSION = 1;
const MAX_TOTP = 5;
const MAX_BACKUP_CODES = 20;
const MAX_UPSTREAMS = 20;
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_UPSTREAM = /^[A-Za-z0-9._~:/-]{1,256}$/;
const RECORD_FIELDS = new Set([
  'v',
  'id',
  'revision',
  'security_version',
  'disabled',
  'mfa_required',
  'password',
  'claims',
  'totp',
  'backup_codes',
  'upstreams',
]);
const TOTP_FIELDS = new Set(['id', 'label', 'secret', 'algorithm', 'digits', 'period', 'last_used_step']);
const BACKUP_FIELDS = new Set(['id', 'hash']);
const UPSTREAM_FIELDS = new Set(['id', 'upstream', 'issuer', 'subject', 'refresh_token']);
const ARGON2ID_RECORD_PROFILE = /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/;

const hasOnlyFields = (value, allowed) => Object.keys(value).every((key) => allowed.has(key));
const approvedArgon2id = (value) =>
  typeof value === 'string' && value.length <= 512 && ARGON2ID_RECORD_PROFILE.test(value);

// Generated once with the same parameters as the provisioning default. It is
// deliberately public: its only job is to make a missing or malformed account
// pay one real Argon2id verification instead of becoming a timing oracle.
const DUMMY_PASSWORD_HASH =
  '$argon2id$v=19$m=65536,t=3,p=1$c2FnLWxvY2FsLWR1bW15MQ$KffQgtYBtmwZAFnvnsXZ7vL8/HU8Mz58bkyIR3r/krU';

const REFRESH_PURPOSE = (identityId, linkId) =>
  'local-identity-refresh/' + identityId + '/' + linkId;

function integer(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  return Number.isSafeInteger(value) && value >= min && value <= max ? value : undefined;
}

/** Does public routing policy offer local authentication for this address? */
export function localIdentityAllowed(config, email) {
  if (config.localIdentities.backend === 'none') return false;
  const domain = domainOf(email);
  if (!domain) return false;
  return config.localIdentities.domains.some((entry) => {
    const wanted = entry.toLowerCase();
    if (wanted === '*') return true;
    if (wanted.startsWith('*.')) {
      const base = wanted.slice(2);
      return domain === base || domain.endsWith('.' + base);
    }
    return domain === wanted;
  });
}

/**
 * HMAC-derived filename for a canonical address.
 *
 * SUBJECT_SALT is deliberately used instead of SAG_SECRET: it is already a
 * high-entropy, non-rotating identity key, so rotating the encryption secret
 * cannot make every local record unreachable. The keyed digest prevents a
 * leaked directory listing becoming an offline list of likely addresses.
 */
export async function localIdentityKey(config, email) {
  const canonical = normaliseEmail(email);
  if (!canonical) throw new Error('a canonical email address is required');
  if (!config.subject.salt) throw new Error('local identity lookup requires SUBJECT_SALT');
  const key = await derive(config.subject.salt, 'local-identity-index', 32);
  return toHex(await hmac(key, canonical));
}

function normaliseTotp(value) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    typeof value.id !== 'string' ||
    !SAFE_ID.test(value.id)
  ) {
    return undefined;
  }
  if (!hasOnlyFields(value, TOTP_FIELDS)) return undefined;
  if (value.algorithm !== undefined && typeof value.algorithm !== 'string') return undefined;
  if (value.digits !== undefined && typeof value.digits !== 'number') return undefined;
  if (value.period !== undefined && typeof value.period !== 'number') return undefined;
  if (value.label !== undefined && typeof value.label !== 'string') return undefined;
  const algorithm = (value.algorithm ?? 'SHA1').toUpperCase().replaceAll('-', '');
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) return undefined;
  const digits = value.digits ?? 6;
  const period = value.period ?? 30;
  if (![6, 8].includes(digits) || integer(period, { min: 15, max: 120 }) === undefined) return undefined;
  if (typeof value.secret !== 'string' || value.secret.length > 256) return undefined;
  let secret;
  try {
    secret = encodeBase32(decodeBase32(value.secret));
  } catch {
    return undefined;
  }
  const lastUsedStep = value.last_used_step;
  if (lastUsedStep !== undefined && integer(lastUsedStep) === undefined) return undefined;
  return {
    id: value.id,
    ...(value.label === undefined ? {} : { label: value.label.slice(0, 128) }),
    secret,
    algorithm,
    digits,
    period,
    ...(lastUsedStep === undefined ? {} : { last_used_step: lastUsedStep }),
  };
}

function normaliseBackup(value) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    typeof value.id !== 'string' ||
    !SAFE_ID.test(value.id)
  ) {
    return undefined;
  }
  if (!hasOnlyFields(value, BACKUP_FIELDS)) return undefined;
  if (!approvedArgon2id(value.hash)) return undefined;
  return { id: value.id.toUpperCase(), hash: value.hash };
}

export function normaliseLocalUpstreamLink(value, index = 0) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  if (!hasOnlyFields(value, UPSTREAM_FIELDS)) return undefined;
  if (
    typeof value.upstream !== 'string' ||
    typeof value.issuer !== 'string' ||
    typeof value.subject !== 'string' ||
    (value.id !== undefined && typeof value.id !== 'string') ||
    (value.refresh_token !== undefined && typeof value.refresh_token !== 'string')
  ) {
    return undefined;
  }
  const { upstream, issuer, subject } = value;
  if (!SAFE_UPSTREAM.test(upstream) || issuer.length < 1 || issuer.length > 2048 || subject.length < 1 || subject.length > 512) {
    return undefined;
  }
  if (
    issuer !== issuer.trim() ||
    [...issuer].some((character) => {
      const code = character.codePointAt(0);
      return code < 0x20 || code === 0x7f;
    })
  ) {
    return undefined;
  }
  let issuerUrl;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    return undefined;
  }
  if (issuerUrl.protocol !== 'https:' && issuerUrl.protocol !== 'http:') return undefined;
  if (issuerUrl.username || issuerUrl.password || issuerUrl.search || issuerUrl.hash) return undefined;
  if (value.refresh_token?.length > 32768) return undefined;
  const id = value.id === undefined ? 'upstream-' + (index + 1) : value.id;
  if (!SAFE_ID.test(id)) return undefined;
  return {
    id,
    upstream,
    // OIDC issuer identifiers are exact strings. URL parsing above validates
    // the shape, but canonicalising host case, a default port, dot segments,
    // or a trailing slash would change the identifier the signed token
    // actually asserted.
    issuer,
    subject,
    ...(typeof value.refresh_token === 'string' ? { refresh_token: value.refresh_token } : {}),
  };
}

/** Strictly validate and bound one stored document. */
export function parseLocalIdentityRecord(config, doc, key) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) || doc.v !== RECORD_VERSION) return undefined;
  if (!hasOnlyFields(doc, RECORD_FIELDS)) return undefined;
  if (typeof doc.id !== 'string' || !SAFE_ID.test(doc.id)) return undefined;
  const revision = integer(doc.revision, { min: 1 });
  const securityVersion = integer(doc.security_version, { min: 1 });
  if (revision === undefined || securityVersion === undefined) return undefined;
  if (!approvedArgon2id(doc.password)) return undefined;
  if (doc.disabled !== undefined && typeof doc.disabled !== 'boolean') return undefined;
  if (doc.mfa_required !== undefined && typeof doc.mfa_required !== 'boolean') return undefined;

  const rawTotp = doc.totp === undefined ? [] : doc.totp;
  const rawBackup = doc.backup_codes === undefined ? [] : doc.backup_codes;
  const rawUpstreams = doc.upstreams === undefined ? [] : doc.upstreams;
  if (!Array.isArray(rawTotp) || rawTotp.length > MAX_TOTP) return undefined;
  if (!Array.isArray(rawBackup) || rawBackup.length > MAX_BACKUP_CODES) return undefined;
  if (!Array.isArray(rawUpstreams) || rawUpstreams.length > MAX_UPSTREAMS) return undefined;
  const totp = rawTotp.map(normaliseTotp);
  const backupCodes = rawBackup.map(normaliseBackup);
  const upstreams = rawUpstreams.map(normaliseLocalUpstreamLink);
  if (totp.includes(undefined) || backupCodes.includes(undefined) || upstreams.includes(undefined)) return undefined;
  if (new Set(totp.map((item) => item.id)).size !== totp.length) return undefined;
  // Replay markers are per credential. Reusing a seed under another id would
  // let the same code spend one unused marker after another.
  if (new Set(totp.map((item) => item.secret)).size !== totp.length) return undefined;
  if (new Set(backupCodes.map((item) => item.id)).size !== backupCodes.length) return undefined;
  if (new Set(upstreams.map((item) => item.id)).size !== upstreams.length) return undefined;
  if (doc.mfa_required === false && (totp.length || backupCodes.length)) return undefined;

  if (
    doc.claims !== undefined &&
    (!doc.claims || typeof doc.claims !== 'object' || Array.isArray(doc.claims))
  ) {
    return undefined;
  }
  if (
    doc.claims &&
    Object.entries(doc.claims).some(
      ([claim, value]) =>
        !PROFILE_CLAIMS.includes(claim) ||
        typeof value !== 'string' ||
        value.length < 1 ||
        value.length > 512 ||
        (claim === 'picture' && !/^https:\/\//i.test(value)),
    )
  ) {
    return undefined;
  }
  return {
    v: RECORD_VERSION,
    id: doc.id,
    revision,
    security_version: securityVersion,
    disabled: doc.disabled === true,
    // Once an identity has required MFA, exhausting its last recovery code
    // must lock it pending operator action, not silently downgrade it to a
    // password-only account. Records without the explicit flag migrate to the
    // safe policy when they contain any factor.
    mfa_required: doc.mfa_required === true || Boolean(totp.length || backupCodes.length),
    password: doc.password,
    totp,
    backup_codes: backupCodes,
    upstreams,
    // Keep the validated source claims intact. The deployment's relay policy
    // is applied only when a session is created; a TOTP replay marker or
    // backup-code update must not erase claims which this instance currently
    // chooses not to disclose.
    claims: doc.claims ? { ...doc.claims } : undefined,
    _key: key,
  };
}

/** Build a JSON-safe document after a state-only update. */
function storedRecord(record) {
  return {
    v: RECORD_VERSION,
    id: record.id,
    revision: record.revision,
    security_version: record.security_version,
    ...(record.disabled ? { disabled: true } : {}),
    ...(record.mfa_required ? { mfa_required: true } : {}),
    password: record.password,
    ...(record.claims ? { claims: record.claims } : {}),
    totp: record.totp.map((item) => ({ ...item })),
    backup_codes: record.backup_codes.map((item) => ({ ...item })),
    upstreams: record.upstreams.map((item) => ({ ...item })),
  };
}

async function openRefreshToken(config, record, link) {
  const purpose = REFRESH_PURPOSE(record.id, link.id);
  let current = true;
  let payload;
  try {
    payload = await unseal(config.secrets[0], purpose, link.refresh_token);
  } catch {
    current = false;
    payload = await unseal(config.secrets, purpose, link.refresh_token);
  }
  if (
    payload?.v !== 1 ||
    payload.identity_id !== record.id ||
    payload.link_id !== link.id ||
    payload.upstream !== link.upstream ||
    payload.issuer !== link.issuer ||
    payload.subject !== link.subject ||
    typeof payload.token !== 'string'
  ) {
    throw new SealError('refresh token is bound to a different identity or upstream link');
  }
  return { token: payload.token, current };
}

function backupSelector(code) {
  const normalised = String(code || '').toUpperCase().replace(/\s/g, '');
  const id = normalised.split('-')[0];
  return SAFE_ID.test(id) ? { id, code: normalised } : undefined;
}

/**
 * Create the local identity service around an adapter binding.
 *
 * The binding owns filesystem mutation and Argon2. Every sensitive value is
 * still interpreted and sealed here, so the platform shim cannot change the
 * authentication contract.
 */
export function createLocalIdentityStore(config, env) {
  if (config.localIdentities.backend === 'none') return undefined;
  const binding = env?.[config.localIdentities.bindingName];
  if (
    !binding ||
    typeof binding.get !== 'function' ||
    typeof binding.replace !== 'function' ||
    typeof binding.verifyArgon2id !== 'function'
  ) {
    throw new Error(
      'LOCAL_IDENTITIES_BACKEND is file, which requires the Node adapter binding ' +
        config.localIdentities.bindingName,
    );
  }

  const find = async (email) => {
    const key = await localIdentityKey(config, email);
    let doc;
    try {
      doc = await binding.get(key);
    } catch (error) {
      // Interactive password handling still has to pay the dummy Argon cost
      // and return its generic page for an unreadable or malformed file. The
      // error is carried for an operator-only log; other uses fail closed.
      return { key, record: undefined, malformed: true, error };
    }
    const record = parseLocalIdentityRecord(config, doc, key);
    return { key, record, malformed: Boolean(doc && !record) };
  };

  const verifyPassword = async (found, password) => {
    const value = String(password || '');
    const withinLimit = utf8(value).length <= config.localIdentities.maxPasswordBytes;
    const hash = withinLimit && found.record && !found.record.disabled ? found.record.password : DUMMY_PASSWORD_HASH;
    let ok;
    try {
      ok = await binding.verifyArgon2id(hash, withinLimit ? value : 'password-too-long');
    } catch {
      // A malformed verifier must behave like a missing record. It is an
      // operator error, but never an account-existence oracle.
      ok = await binding.verifyArgon2id(DUMMY_PASSWORD_HASH, withinLimit ? value : 'password-too-long');
    }
    return Boolean(ok && withinLimit && found.record && !found.record.disabled);
  };

  const replace = async (record, mutate) => {
    const next = mutate({
      ...record,
      totp: record.totp.map((item) => ({ ...item })),
      backup_codes: record.backup_codes.map((item) => ({ ...item })),
      upstreams: record.upstreams.map((item) => ({ ...item })),
    });
    next.revision = record.revision + 1;
    const written = await binding.replace(record._key, record.revision, storedRecord(next));
    return written ? { ...next, _key: record._key } : undefined;
  };

  const verifySecondFactor = async (record, code, now = Date.now(), { consume = true } = {}) => {
    const selector = backupSelector(code);
    const backup = selector && record.backup_codes.find((item) => item.id === selector.id);
    if (backup) {
      let ok = false;
      try {
        ok = await binding.verifyArgon2id(backup.hash, selector.code);
      } catch {
        // A broken verifier is an unusable recovery code, not a reason to
        // expose an operator error to somebody on the factor screen.
      }
      if (!ok) return undefined;
      if (!consume) return { method: 'recovery', record };
      const updated = await replace(record, (next) => {
        next.backup_codes = next.backup_codes.filter((item) => item.id !== backup.id);
        return next;
      });
      return updated ? { method: 'recovery', record: updated } : undefined;
    }

    for (const credential of record.totp) {
      const step = await verifyTotp({
        secret: credential.secret,
        code,
        now,
        algorithm: credential.algorithm,
        digits: credential.digits,
        period: credential.period,
        skew: config.localIdentities.totpSkew,
        lastUsedStep: credential.last_used_step,
      });
      if (step === undefined) continue;
      if (!consume) return { method: 'totp', record };
      const updated = await replace(record, (next) => {
        const held = next.totp.find((item) => item.id === credential.id);
        if (held) held.last_used_step = step;
        return next;
      });
      return updated ? { method: 'totp', record: updated } : undefined;
    }
    return undefined;
  };

  const validateSession = async (session) => {
    if (!session?.localIdentityId) return true;
    const key = session.localIdentityKey;
    const found = /^[0-9a-f]{64}$/.test(String(key || ''))
      ? { key, record: parseLocalIdentityRecord(config, await binding.get(key), key) }
      : await find(session.email);
    return Boolean(
      found.record &&
      !found.record.disabled &&
      found.record.id === session.localIdentityId &&
      found.record.security_version === session.localSecurityVersion,
    );
  };

  const linked = async (email, { upstream, issuer, subject }) => {
    const found = await find(email);
    if (found.error) throw found.error;
    if (!found.record || found.record.disabled) return undefined;
    const link = found.record.upstreams.find(
      (item) => item.upstream === upstream && item.issuer === issuer && item.subject === subject,
    );
    return link ? { ...found, link } : undefined;
  };

  const storeRefreshToken = async (record, link, token) => {
    if (!token) return record;
    if (String(token).length > 16384) throw new Error('upstream refresh credential is too large to retain');
    const payload = {
      v: 1,
      identity_id: record.id,
      link_id: link.id,
      upstream: link.upstream,
      issuer: link.issuer,
      subject: link.subject,
      token: String(token),
    };
    const ciphertext = await seal(config.secrets[0], REFRESH_PURPOSE(record.id, link.id), payload);
    return replace(record, (next) => {
      const held = next.upstreams.find((item) => item.id === link.id);
      if (held) held.refresh_token = ciphertext;
      return next;
    });
  };

  const rekeyRecord = async (record) => {
    const upstreams = [];
    let changed = false;
    for (const link of record.upstreams) {
      if (!link.refresh_token) {
        upstreams.push({ ...link });
        continue;
      }
      const opened = await openRefreshToken(config, record, link);
      if (!opened.current) changed = true;
      upstreams.push({
        ...link,
        refresh_token: opened.current
          ? link.refresh_token
          : await sealUpstreamRefreshToken(config, record.id, link, opened.token),
      });
    }
    if (!changed) return { record, changed: false };
    const updated = await replace(record, (next) => ({ ...next, upstreams }));
    if (!updated) throw new Error('local identity changed while it was being rekeyed');
    return { record: updated, changed: true };
  };

  const rekeyAll = async () => {
    if (typeof binding.list !== 'function') throw new Error('the local identity binding cannot list records');
    let changed = 0;
    let unchanged = 0;
    for (const filename of await binding.list()) {
      const key = filename.replace(/\.json$/, '');
      const record = parseLocalIdentityRecord(config, await binding.get(key), key);
      if (!record) throw new Error('local identity record ' + filename + ' is malformed');
      const result = await rekeyRecord(record);
      if (result.changed) changed += 1;
      else unchanged += 1;
    }
    return { changed, unchanged };
  };

  return {
    backend: 'file',
    binding,
    find,
    verifyPassword,
    verifySecondFactor,
    validateSession,
    linked,
    storeRefreshToken,
    rekeyRecord,
    rekeyAll,
    profileClaims: (record) => relayedClaims(config, record?.claims),
    requiresSecondFactor: (record) => record?.mfa_required === true,
  };
}

/** Seal a pre-provisioned upstream refresh credential. */
export const sealUpstreamRefreshToken = (config, identityId, link, token) =>
  seal(config.secrets[0], REFRESH_PURPOSE(identityId, link.id), {
    v: 1,
    identity_id: identityId,
    link_id: link.id,
    upstream: link.upstream,
    issuer: link.issuer,
    subject: link.subject,
    token,
  });

/** Fresh opaque identifiers for the provisioning tool. */
export const newLocalIdentityId = () => randomToken(18);
export const newCredentialId = () => b64u(crypto.getRandomValues(new Uint8Array(9)));
