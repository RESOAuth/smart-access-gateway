// Authentication context: how SAG describes the strength of an authentication
// and how it decides whether a relying party's demand has been met.

export const ACR = {
  OTP: 'urn:sag:acr:email-otp',
  LOCAL_PASSWORD: 'urn:sag:acr:local-password',
  LOCAL_MFA: 'urn:sag:acr:local-mfa',
  FEDERATED: 'urn:sag:acr:federated',
  FEDERATED_MFA: 'urn:sag:acr:federated-mfa',
  MFA: 'urn:sag:acr:mfa',
};

/** Ordered weakest to strongest. A stronger authentication satisfies a weaker demand. */
export const ACR_STRENGTH = {
  [ACR.OTP]: 1,
  [ACR.FEDERATED]: 2,
  [ACR.FEDERATED_MFA]: 3,
};

// eslint-disable-next-line security/detect-object-injection -- lookup in fixed ACR_STRENGTH mapping
export const strengthOf = (acr) => ACR_STRENGTH[acr] ?? 0;

/**
 * Upstream authentication method references we recognise. Anything else from
 * an upstream is passed through untouched so relying parties can inspect it.
 */
export const AMR = {
  OTP: 'otp',
  EMAIL: 'email',
  FEDERATED: 'fed',
  MFA: 'mfa',
  PASSWORD: 'pwd',
  HARDWARE_KEY: 'hwk',
  PASSKEY: 'swk',
  RECOVERY: 'recovery',
};

const MFA_HINTS = new Set(['mfa', 'otp', 'sms', 'swk', 'hwk', 'fido', 'phr', 'phrh', 'mca', 'face', 'fpt']);

// An upstream's `amr` ends up in the session cookie, the authorisation code and
// the id_token, so it is bounded here rather than trusted to be sensible. A real
// one has a handful of short tokens in it; anything beyond that is either broken
// or an attempt to make a cookie the browser will drop.
const MAX_AMR_VALUES = 16;
const MAX_AMR_LENGTH = 32;

/**
 * Derive our acr and amr from an upstream id_token.
 * Microsoft reports MFA in `amr`; Google reports it only indirectly, so a
 * federated sign-in without evidence of MFA stays at FEDERATED.
 *
 * An over-long or over-numerous `amr` is bounded rather than refused: what it
 * says about the strength of the authentication is still read from everything
 * the upstream sent, and only what is carried onwards is trimmed.
 */
export function acrFromUpstream(upstreamClaims = {}) {
  const raw = upstreamClaims.amr;
  const all = Array.isArray(raw) ? raw.filter((v) => typeof v === 'string') : typeof raw === 'string' ? [raw] : [];
  const amr = all.filter((v) => v.length <= MAX_AMR_LENGTH).slice(0, MAX_AMR_VALUES);
  const normalised = [AMR.FEDERATED, ...amr];
  const mfa = all.some((v) => MFA_HINTS.has(v.toLowerCase())) || all.length > 1;
  if (mfa && !normalised.includes(AMR.MFA)) normalised.push(AMR.MFA);
  return {
    acr: mfa ? ACR.FEDERATED_MFA : ACR.FEDERATED,
    amr: [...new Set(normalised)],
    upstreamAcr: typeof upstreamClaims.acr === 'string' ? upstreamClaims.acr : undefined,
  };
}

export function acrForOtp() {
  return { acr: ACR.OTP, amr: [AMR.OTP, AMR.EMAIL] };
}

export function acrForLocal(secondFactor) {
  if (!secondFactor) return { acr: ACR.LOCAL_PASSWORD, amr: [AMR.PASSWORD] };
  return {
    acr: ACR.LOCAL_MFA,
    amr: [AMR.PASSWORD, secondFactor === 'totp' ? AMR.OTP : AMR.RECOVERY, AMR.MFA],
  };
}

/**
 * Does `held` satisfy the relying party's `requested` acr_values?
 * An empty request is always satisfied. Unknown requested values must match
 * exactly, so a bespoke acr can never be silently downgraded.
 */
export function satisfies(held, requested) {
  if (!requested || requested.length === 0) return true;
  const local = held === ACR.LOCAL_PASSWORD || held === ACR.LOCAL_MFA;
  const heldStrength = strengthOf(held);
  return requested.some((want) => {
    // This request leaves the authentication method open; the held context
    // still records which method actually established MFA.
    if (want === ACR.MFA) return held === ACR.LOCAL_MFA || held === ACR.FEDERATED_MFA;
    if (want === held) return true;
    // Authentication method is part of these names. A high-assurance local
    // sign-in must not silently satisfy a demand specifically for federation,
    // nor may a federated session stand in for a requested local account.
    if (local || want === ACR.LOCAL_PASSWORD || want === ACR.LOCAL_MFA) {
      return held === ACR.LOCAL_MFA && want === ACR.LOCAL_PASSWORD;
    }
    const wantStrength = strengthOf(want);
    return wantStrength > 0 && heldStrength >= wantStrength;
  });
}

/** The weakest method that could satisfy the request, for routing decisions. */
export function minimumStrengthRequired(requested) {
  if (!requested || requested.length === 0) return 0;
  const known = requested
    .map((want) => strengthOf(want === ACR.MFA ? ACR.FEDERATED_MFA : want))
    .filter((s) => s > 0);
  return known.length ? Math.min(...known) : Infinity;
}

/** True when email OTP alone could never satisfy the request. */
export function requiresFederation(requested) {
  return minimumStrengthRequired(requested) > ACR_STRENGTH[ACR.OTP];
}

export const SUPPORTED_ACR_VALUES = Object.values(ACR);
export const SUPPORTED_AMR_VALUES = Object.values(AMR);
