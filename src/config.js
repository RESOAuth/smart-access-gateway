// Configuration is derived entirely from environment variables so that the
// same build runs unchanged on Workers, Lambda, and a local Node process.
//
// Two rules shape everything here. First, local development must work with no
// configuration at all. Second, the moment a real hostname is in play, every
// development default becomes a hard error rather than a quiet weakness.

import { ALGS, isPostQuantum } from './crypto/jose.js';
import { SUPPORTED_ACR_VALUES } from './acr.js';

const DEV_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0', 'host.docker.internal']);

// Suffixes that only ever name a machine you are sitting at. `.linux.test` is
// how ChromeOS names a Crostini container from the browser, which runs outside
// the Linux VM and therefore cannot reach its localhost at all.
const DEV_SUFFIXES = ['.localhost', '.local', '.linux.test'];

const isDevHostname = (hostname) =>
  DEV_HOSTNAMES.has(hostname) || DEV_SUFFIXES.some((suffix) => hostname.endsWith(suffix));

// ---------------------------------------------------------------------------
// Primitive readers
// ---------------------------------------------------------------------------

const str = (env, key, fallback) => {
  const v = env[key];
  return v === undefined || v === null || String(v).trim() === '' ? fallback : String(v).trim();
};

function bool(env, key, fallback = false) {
  const v = str(env, key);
  if (v === undefined) return fallback;
  const l = v.toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled'].includes(l)) return true;
  if (['0', 'false', 'no', 'off', 'disabled'].includes(l)) return false;
  throw new ConfigError(key + ' must be a boolean, got "' + v + '"');
}

function int(env, key, fallback, { min, max } = {}) {
  const v = str(env, key);
  if (v === undefined) return fallback;
  const n = Number(v);
  if (!Number.isInteger(n)) throw new ConfigError(key + ' must be a whole number, got "' + v + '"');
  if (min !== undefined && n < min) throw new ConfigError(key + ' must be at least ' + min);
  if (max !== undefined && n > max) throw new ConfigError(key + ' must be at most ' + max);
  return n;
}

/** Comma or space separated list. */
function list(env, key, fallback = []) {
  const v = str(env, key);
  if (v === undefined) return fallback;
  return v
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function jsonValue(env, key, fallback) {
  const v = str(env, key);
  if (v === undefined) return fallback;
  try {
    return JSON.parse(v);
  } catch (cause) {
    throw new ConfigError(key + ' must be valid JSON: ' + cause.message);
  }
}

function oneOf(env, key, allowed, fallback) {
  const v = str(env, key, fallback);
  if (!allowed.includes(v)) {
    throw new ConfigError(key + ' must be one of ' + allowed.join(', ') + ', got "' + v + '"');
  }
  return v;
}

/**
 * The first of several environment variable names that is actually set.
 *
 * Variables get renamed as a project learns what a thing really is, and an
 * operator should not have to rewrite their deployment for it. The name that
 * won is returned rather than its value, so an error message names the
 * variable the operator actually set.
 */
function alias(env, names) {
  for (const name of names) if (str(env, name) !== undefined) return name;
  return names[0];
}

/**
 * Where an AWS service actually lives.
 *
 * SAG signs its own requests to KMS, DynamoDB and S3 rather than carrying an
 * SDK, so pointing one somewhere else needs nothing but a base URL: a local
 * emulator, DynamoDB Local, MinIO, an S3-compatible bucket, or the mock in
 * test/local-stack. The variable names are the SDK's own, so an environment
 * already set up for an emulator works here unchanged.
 *
 * @param {string} service Suffix as the AWS SDK spells it, e.g. 'KMS'
 * @returns {string|undefined} Base URL with no trailing slash
 */
function awsEndpoint(env, service) {
  const key = alias(env, ['AWS_ENDPOINT_URL_' + service, 'AWS_ENDPOINT_URL']);
  const raw = str(env, key);
  if (raw === undefined) return undefined;
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(key + ' must be an absolute URL, got "' + raw + '"');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConfigError(key + ' must be an http or https URL, got "' + raw + '"');
  }
  return (url.origin + url.pathname).replace(/\/+$/, '');
}

/**
 * How long a one-time code is.
 *
 * Nine is the floor rather than a preference: six digits with an attempt
 * counter that can be rolled back is a one in a million guess with unlimited
 * attempts. A deployment that pinned the old default with OTP_DIGITS=6 is
 * raised to nine and told, rather than refused a start, because refusing to
 * boot on upgrade is a worse failure than a longer code.
 */
function codeLength(env, warnings) {
  const key = alias(env, ['OTP_CODE_LENGTH', 'OTP_DIGITS']);
  const requested = int(env, key, 9, { min: 1, max: 12 });
  if (requested >= 9) return requested;
  warnings.push(
    key + ' is ' + requested + ', which is below the minimum of 9, so 9 is being used. See docs/limitations.md.',
  );
  return 9;
}

/**
 * The profile claims SAG is willing to carry.
 *
 * Standard OpenID Connect claim names only, and only ones an upstream actually
 * returns often enough to be worth relaying. Anything not on this list is
 * dropped rather than passed through, so an upstream cannot use SAG to inject
 * arbitrary claims into a relying party's id_token.
 */
export const PROFILE_CLAIMS = [
  'name',
  'given_name',
  'family_name',
  'middle_name',
  'nickname',
  'preferred_username',
  'picture',
  'locale',
  'zoneinfo',
];

const DEFAULT_PROFILE_CLAIMS = ['name', 'given_name', 'family_name', 'preferred_username', 'picture', 'locale'];

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

/** Turn an algorithm name into an environment-variable-safe suffix. */
export const algEnvSuffix = (alg) => alg.toUpperCase().replaceAll('-', '_');

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

function resolveIssuer(env, requestUrl) {
  const explicit = str(env, 'SAG_ISSUER');
  if (explicit) {
    let u;
    try {
      u = new URL(explicit);
    } catch {
      throw new ConfigError('SAG_ISSUER must be an absolute URL, got "' + explicit + '"');
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
      throw new ConfigError('SAG_ISSUER must be an http or https URL, got "' + explicit + '"');
    }
    if (!u.hostname) throw new ConfigError('SAG_ISSUER must name a host, got "' + explicit + '"');
    if (u.username || u.password) throw new ConfigError('SAG_ISSUER must not contain a username or password');
    if (u.search || u.hash) throw new ConfigError('SAG_ISSUER must not contain a query or fragment');
    // An issuer identifier has no trailing slash, so that string comparison
    // against the `iss` claim is unambiguous.
    const normalised = (u.origin + u.pathname).replace(/\/+$/, '');
    return { issuer: normalised, derived: false };
  }
  if (!requestUrl) throw new ConfigError('SAG_ISSUER is not set and no request URL is available to derive it from');
  const u = new URL(requestUrl);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new ConfigError('The request URL used to derive SAG_ISSUER must be http or https');
  }
  return { issuer: u.origin, derived: true };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

function readSigning(env, devMode, problems) {
  const backend = oneOf(env, 'SIGNING_BACKEND', ['local', 'cloudflare-hsm', 'aws-kms'], 'local');
  const alg = str(env, 'SIGNING_ALG', 'ES256');
  if (!ALGS[alg] || ALGS[alg].family === 'symmetric') {
    throw new ConfigError('SIGNING_ALG must be an asymmetric JWS algorithm, got "' + alg + '"');
  }

  const additionalAlgs = list(env, 'SIGNING_ADDITIONAL_ALGS').filter((a) => a !== alg);
  for (const a of additionalAlgs) {
    if (!ALGS[a] || ALGS[a].family === 'symmetric') {
      throw new ConfigError('SIGNING_ADDITIONAL_ALGS contains an unusable algorithm: "' + a + '"');
    }
  }

  // Per-algorithm key material, so a classical and a post-quantum key can be
  // configured side by side: SIGNING_PRIVATE_JWK_ML_DSA_44, and so on.
  const keysByAlg = {};
  for (const a of [alg, ...additionalAlgs]) {
    const suffix = algEnvSuffix(a);
    keysByAlg[a] = {
      privateJwk: jsonValue(env, 'SIGNING_PRIVATE_JWK_' + suffix),
      privatePem: str(env, 'SIGNING_PRIVATE_KEY_PEM_' + suffix),
      kmsKeyId: str(env, 'SIGNING_KMS_KEY_ID_' + suffix),
    };
  }
  // Unsuffixed variables configure the primary algorithm.
  keysByAlg[alg] = {
    privateJwk: keysByAlg[alg].privateJwk ?? jsonValue(env, 'SIGNING_PRIVATE_JWK'),
    privatePem: keysByAlg[alg].privatePem ?? str(env, 'SIGNING_PRIVATE_KEY_PEM'),
    kmsKeyId: keysByAlg[alg].kmsKeyId ?? str(env, 'SIGNING_KMS_KEY_ID'),
  };

  // REQUIRE_* is the shape every "turn a silent fallback into a startup
  // error" flag takes, so an operator only has to learn the pattern once.
  // The old name still works: see alias() above.
  const requirePostQuantumKey = alias(env, ['REQUIRE_POST_QUANTUM_SIGNING', 'SIGNING_REQUIRE_POST_QUANTUM']);
  const requirePostQuantum = bool(env, requirePostQuantumKey, false);
  if (requirePostQuantum && ![alg, ...additionalAlgs].some(isPostQuantum)) {
    throw new ConfigError(
      requirePostQuantumKey + ' is set but neither SIGNING_ALG nor SIGNING_ADDITIONAL_ALGS names a post-quantum algorithm',
    );
  }

  const signing = {
    backend,
    alg,
    additionalAlgs,
    keysByAlg,
    requirePostQuantum,
    privateJwk: keysByAlg[alg].privateJwk,
    privatePem: keysByAlg[alg].privatePem,
    extraPublicJwks: jsonValue(env, 'SIGNING_PUBLIC_JWKS_EXTRA', []),
    hsmBindingName: str(env, 'HSM_BINDING', 'HSM'),
    hsmBinding: str(env, 'HSM_URL'),
    hsmSharedSecret: str(env, 'HSM_SHARED_SECRET'),
    kmsKeyId: keysByAlg[alg].kmsKeyId,
    kmsRegion: str(env, 'SIGNING_KMS_REGION', str(env, 'AWS_REGION')),
    kmsEndpoint: awsEndpoint(env, 'KMS'),
  };

  if (!Array.isArray(signing.extraPublicJwks)) {
    throw new ConfigError('SIGNING_PUBLIC_JWKS_EXTRA must be a JSON array of public JWKs');
  }

  if (backend === 'local' && !signing.privateJwk && !signing.privatePem && !devMode) {
    problems.push(
      'No signing key is configured. Set SIGNING_PRIVATE_JWK (or SIGNING_PRIVATE_KEY_PEM), or switch SIGNING_BACKEND to cloudflare-hsm or aws-kms. An ephemeral key would invalidate every token whenever the instance restarts.',
    );
  }
  if (backend === 'cloudflare-hsm' && !signing.hsmSharedSecret) {
    problems.push('SIGNING_BACKEND is cloudflare-hsm but HSM_SHARED_SECRET is not set.');
  }
  if (backend === 'aws-kms') {
    if (!signing.kmsKeyId) problems.push('SIGNING_BACKEND is aws-kms but SIGNING_KMS_KEY_ID is not set.');
    if (!signing.kmsRegion) problems.push('SIGNING_BACKEND is aws-kms but neither SIGNING_KMS_REGION nor AWS_REGION is set.');
  }
  return signing;
}

// ---------------------------------------------------------------------------
// Upstream identity providers
// ---------------------------------------------------------------------------

const UPSTREAM_FIELDS = [
  'CLIENT_ID',
  'CLIENT_SECRET',
  'TENANT',
  'SCOPES',
  'ISSUER',
  'AUTHORIZATION_ENDPOINT',
  'TOKEN_ENDPOINT',
  'JWKS_URI',
  'HD',
  'LABEL',
  'PROMPT',
  'ACR_VALUES',
  'ENABLED',
  'DISCOVERY',
  'MAIL_PROVIDER',
];

/**
 * Parse UPSTREAM_<PROVIDER>_<SLUG>_<FIELD> variables into upstream records.
 *
 * The domain a record serves cannot live in the variable name, because
 * environment variable names cannot contain dots. It is therefore carried as a
 * prefix on the client id value, exactly as the project brief describes:
 *
 *   UPSTREAM_MICROSOFT_COMMON_CLIENT_ID=common:0000-1111
 *   UPSTREAM_MICROSOFT_EXAMPLECOM_CLIENT_ID=example.com:2222-3333
 */
function readUpstreams(env, problems) {
  const grouped = new Map();
  for (const key of Object.keys(env)) {
    if (!key.startsWith('UPSTREAM_')) continue;
    const rest = key.slice('UPSTREAM_'.length);
    const field = UPSTREAM_FIELDS.filter((f) => rest === f || rest.endsWith('_' + f)).sort(
      (a, b) => b.length - a.length,
    )[0];
    if (!field) {
      problems.push('Ignoring ' + key + ': "' + rest + '" does not end in a known upstream field.');
      continue;
    }
    const head = rest.slice(0, rest.length - field.length).replace(/_$/, '');
    const underscore = head.indexOf('_');
    if (underscore < 1) {
      problems.push('Ignoring ' + key + ': expected UPSTREAM_<PROVIDER>_<SLUG>_' + field + '.');
      continue;
    }
    const provider = head.slice(0, underscore).toLowerCase();
    const slug = head.slice(underscore + 1);
    const id = provider + '/' + slug.toLowerCase();
    if (!grouped.has(id)) grouped.set(id, { id, provider, slug, fields: {} });
    grouped.get(id).fields[field] = str(env, key);
  }

  const upstreams = [];
  for (const record of grouped.values()) {
    const { provider, slug, fields } = record;
    if (fields.ENABLED !== undefined && ['0', 'false', 'no', 'off'].includes(fields.ENABLED.toLowerCase())) continue;
    const rawClientId = fields.CLIENT_ID;
    if (!rawClientId) {
      problems.push('Upstream ' + record.id + ' has no CLIENT_ID and was ignored.');
      continue;
    }
    // Split the "<domain>:<client id>" prefix at the first colon.
    let domain;
    let clientId;
    const colon = rawClientId.indexOf(':');
    if (colon > 0) {
      domain = rawClientId.slice(0, colon).toLowerCase();
      clientId = rawClientId.slice(colon + 1);
    } else if (slug.toUpperCase() === 'COMMON') {
      domain = 'common';
      clientId = rawClientId;
    } else {
      problems.push(
        'Upstream ' + record.id + ' CLIENT_ID must be prefixed with the domain it serves, for example "example.com:' + rawClientId.slice(0, 8) + '...".',
      );
      continue;
    }
    if (!clientId) {
      problems.push('Upstream ' + record.id + ' has an empty client id after the domain prefix.');
      continue;
    }
    if (domain !== 'common' && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
      problems.push('Upstream ' + record.id + ' has an invalid domain prefix "' + domain + '".');
      continue;
    }

    upstreams.push({
      id: record.id,
      provider,
      slug: slug.toLowerCase(),
      domain,
      isCommon: domain === 'common',
      clientId,
      clientSecret: fields.CLIENT_SECRET,
      tenant: fields.TENANT,
      scopes: fields.SCOPES ? fields.SCOPES.split(/[,\s]+/).filter(Boolean) : undefined,
      issuer: fields.ISSUER,
      authorizationEndpoint: fields.AUTHORIZATION_ENDPOINT,
      tokenEndpoint: fields.TOKEN_ENDPOINT,
      jwksUri: fields.JWKS_URI,
      hd: fields.HD,
      label: fields.LABEL,
      prompt: fields.PROMPT,
      acrValues: fields.ACR_VALUES ? fields.ACR_VALUES.split(/[,\s]+/).filter(Boolean) : undefined,
      useDiscovery: fields.DISCOVERY === undefined ? undefined : !['0', 'false', 'no', 'off'].includes(fields.DISCOVERY.toLowerCase()),
      // Which mail fingerprint this upstream answers to, for the DNS hint in
      // src/upstream/dns.js. Only needed for a provider SAG has no built-in
      // name for: a Yahoo or an Apple upstream configured as generic OIDC.
      mailProvider: fields.MAIL_PROVIDER ? fields.MAIL_PROVIDER.toLowerCase() : undefined,
    });
  }
  // Domain-specific entries are checked before the common ones.
  upstreams.sort((a, b) => Number(a.isCommon) - Number(b.isCommon) || a.id.localeCompare(b.id));
  return upstreams;
}

// ---------------------------------------------------------------------------
// Statically configured relying parties
// ---------------------------------------------------------------------------

const CLIENT_FIELDS = [
  'ID',
  'SECRET',
  'REDIRECT_URIS',
  'POST_LOGOUT_REDIRECT_URIS',
  'NAME',
  'JWKS',
  'JWKS_URI',
  'AUTH_METHOD',
  'SCOPES',
  'ACR_VALUES',
  'ID_TOKEN_SIGNED_RESPONSE_ALG',
  'SESSION_SCOPE',
  'REQUIRE_PKCE',
  'LOGOUT_CONFIRM',
  'TOS_URI',
  'POLICY_URI',
  'SANITISE_PLUS_EMAILS',
];

/**
 * A per-client override is only useful if it is one of the values we act on.
 *
 * Ignoring a typo silently would leave an interstitial the operator thought
 * they had turned off and nothing to explain it, so it is reported the same
 * way every other client misconfiguration here is.
 */
/**
 * A client's token endpoint authentication method has to be one we implement.
 *
 * A typo here used to be invisible: the client would be configured with a
 * method nothing checks, and discovery would then describe the deployment from
 * a set of methods containing it. Reported the same way every other client
 * misconfiguration is, and the client is dropped rather than half-configured.
 */
const CLIENT_AUTH_METHODS = ['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'];

function authMethodValue(slug, value, defaultMethod, problems) {
  if (value === undefined) return defaultMethod;
  const v = String(value).toLowerCase();
  if (CLIENT_AUTH_METHODS.includes(v)) return v;
  problems.push(
    'Client ' + slug + ' has AUTH_METHOD="' + value + '", which is not one of ' + CLIENT_AUTH_METHODS.join(', ') + '.',
  );
  return undefined;
}

/**
 * A per-client boolean override, where "not set" has to stay distinguishable
 * from "set to false": undefined means the client inherits the instance
 * default, which is not the same answer as choosing the same value.
 */
function clientBool(slug, field, value, problems) {
  if (value === undefined) return undefined;
  const l = String(value).toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled'].includes(l)) return true;
  if (['0', 'false', 'no', 'off', 'disabled'].includes(l)) return false;
  problems.push('CLIENT_' + slug + '_' + field + ' must be a boolean, got "' + value + '".');
  return undefined;
}

function logoutConfirmValue(slug, value, problems) {
  if (value === undefined) return undefined;
  const v = String(value).toLowerCase();
  if (['auto', 'always', 'never'].includes(v)) return v;
  problems.push(
    'CLIENT_' + slug + '_LOGOUT_CONFIRM must be auto, always or never, got "' + value + '"; ignoring it and using the instance default.',
  );
  return undefined;
}

function readStaticClients(env, problems) {
  const grouped = new Map();
  for (const key of Object.keys(env)) {
    if (!key.startsWith('CLIENT_')) continue;
    const rest = key.slice('CLIENT_'.length);
    const field = CLIENT_FIELDS.filter((f) => rest === f || rest.endsWith('_' + f)).sort((a, b) => b.length - a.length)[0];
    if (!field) continue;
    const slug = rest.slice(0, rest.length - field.length).replace(/_$/, '');
    if (!slug) continue;
    if (!grouped.has(slug)) grouped.set(slug, {});
    grouped.get(slug)[field] = str(env, key);
  }

  const clients = [];
  for (const [slug, fields] of grouped) {
    const clientId = fields.ID;
    if (!clientId) {
      problems.push('Static client ' + slug + ' has no CLIENT_' + slug + '_ID and was ignored.');
      continue;
    }
    const redirectUris = (fields.REDIRECT_URIS || '').split(/[,\s]+/).filter(Boolean);
    if (redirectUris.length === 0) {
      problems.push('Static client ' + slug + ' has no CLIENT_' + slug + '_REDIRECT_URIS and was ignored.');
      continue;
    }
    let jwks;
    if (fields.JWKS) {
      try {
        jwks = JSON.parse(fields.JWKS);
      } catch (cause) {
        problems.push('Static client ' + slug + ' has invalid JSON in CLIENT_' + slug + '_JWKS: ' + cause.message);
      }
    }
    const hasSecret = Boolean(fields.SECRET);
    const hasKeys = Boolean(jwks || fields.JWKS_URI);
    const defaultMethod = hasKeys ? 'private_key_jwt' : hasSecret ? 'client_secret_basic' : 'none';
    const authMethod = authMethodValue(slug, fields.AUTH_METHOD, defaultMethod, problems);
    if (authMethod === undefined) continue;
    clients.push({
      source: 'static',
      slug,
      clientId,
      clientName: fields.NAME || slug,
      clientSecret: fields.SECRET,
      redirectUris,
      postLogoutRedirectUris: (fields.POST_LOGOUT_REDIRECT_URIS || '').split(/[,\s]+/).filter(Boolean),
      jwks,
      jwksUri: fields.JWKS_URI,
      tokenEndpointAuthMethod: authMethod,
      scopes: (fields.SCOPES || '').split(/[,\s]+/).filter(Boolean),
      acrValues: (fields.ACR_VALUES || '').split(/[,\s]+/).filter(Boolean),
      idTokenSignedResponseAlg: fields.ID_TOKEN_SIGNED_RESPONSE_ALG,
      sessionScope: fields.SESSION_SCOPE,
      logoutConfirm: logoutConfirmValue(slug, fields.LOGOUT_CONFIRM, problems),
      tosUri: fields.TOS_URI,
      policyUri: fields.POLICY_URI,
      sanitisePlusEmails: clientBool(slug, 'SANITISE_PLUS_EMAILS', fields.SANITISE_PLUS_EMAILS, problems),
      requirePkce: fields.REQUIRE_PKCE === undefined ? true : !['0', 'false', 'no', 'off'].includes(fields.REQUIRE_PKCE.toLowerCase()),
    });
  }
  return clients;
}

// ---------------------------------------------------------------------------
// Peer deployments (JWKS federation)
// ---------------------------------------------------------------------------

/**
 * Parse PEER_JWKS_URLS: the full JWKS URL of every other instance answering
 * as this same issuer, so this instance's own /jwks.json can vouch for their
 * keys too. See docs/multi-region.md.
 *
 * A malformed or non-https entry is dropped rather than refusing the whole
 * deployment to start, the same tolerance readUpstreams and readStaticClients
 * give one bad entry among several: a typo in one peer should cost this
 * instance that one peer's keys, not its ability to run at all.
 */
function readPeerJwksUrls(env, devMode, warnings) {
  const urls = [];
  for (const raw of list(env, 'PEER_JWKS_URLS')) {
    let u;
    try {
      u = new URL(raw);
    } catch {
      warnings.push('Ignoring PEER_JWKS_URLS entry "' + raw + '": not an absolute URL.');
      continue;
    }
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && devMode)) {
      warnings.push('Ignoring PEER_JWKS_URLS entry "' + raw + '": must be an https URL outside development.');
      continue;
    }
    urls.push(u.href);
  }
  return urls;
}

// ---------------------------------------------------------------------------
// Top level
// ---------------------------------------------------------------------------

/**
 * Build the resolved configuration.
 *
 * @param {object} env      Environment bag (process.env, Workers env, and so on)
 * @param {object} [opts]
 * @param {string} [opts.requestUrl] Used to derive the issuer when unset
 */
export function loadConfig(env = {}, opts = {}) {
  const problems = [];
  const warnings = [];
  const internalWarnings = [];

  const { issuer, derived } = resolveIssuer(env, opts.requestUrl);
  const issuerUrl = new URL(issuer);
  const devMode = bool(env, 'SAG_DEV', isDevHostname(issuerUrl.hostname));
  const insecureTransport = issuerUrl.protocol === 'http:';

  if (insecureTransport && !devMode) {
    problems.push('SAG_ISSUER uses http. Cookies and tokens must only travel over TLS outside local development.');
  }

  // --- Master secret -------------------------------------------------------
  const secretsList = [str(env, 'SAG_SECRET'), str(env, 'SAG_SECRET_PREVIOUS')].filter(Boolean);
  if (secretsList.length === 0) {
    if (devMode) {
      // Stable across restarts so that a developer's session survives a reload.
      secretsList.push('sag-development-only-secret-do-not-use-in-production');
      warnings.push('SAG_SECRET is not set; using the well-known development secret. Never do this outside local development.');
    } else {
      problems.push('SAG_SECRET is required. Generate one with: openssl rand -base64 48');
    }
  } else if (secretsList[0].length < 32 && !devMode) {
    problems.push('SAG_SECRET must be at least 32 characters of high-entropy material.');
  }

  const signing = readSigning(env, devMode, problems);
  // Both name the thing they could not parse - an upstream id carries the
  // domain it serves, a client slug is a relying party - so they go where only
  // the operator reads them.
  const upstreams = readUpstreams(env, internalWarnings);
  const staticClients = readStaticClients(env, internalWarnings);

  // With nothing configured at all there would be no relying party to try the
  // flow with, so development mode supplies one. Its redirect URIs are all
  // loopback, so it is useless to anybody who is not already on the machine.
  if (devMode && staticClients.length === 0) {
    staticClients.push({
      source: 'dev-default',
      slug: 'DEV',
      clientId: 'sag-dev-client',
      clientName: 'SAG development client',
      clientSecret: undefined,
      redirectUris: [
        'http://127.0.0.1:8788/callback',
        'http://localhost:8788/callback',
        'http://127.0.0.1:8788/',
      ],
      postLogoutRedirectUris: ['http://127.0.0.1:8788/', 'http://localhost:8788/'],
      tokenEndpointAuthMethod: 'none',
      scopes: [],
      acrValues: [],
      requirePkce: true,
    });
    warnings.push('No relying parties are configured; the development client "sag-dev-client" is available on loopback only.');
  }

  const otpEnabled = bool(env, 'OTP_ENABLED', true);
  const emailProvider = oneOf(
    env,
    'EMAIL_PROVIDER',
    ['console', 'ses', 'notify', 'mailchannels', 'cloudflare', 'smtp'],
    devMode ? 'console' : 'console',
  );
  if (otpEnabled && emailProvider === 'console' && !devMode) {
    problems.push('EMAIL_PROVIDER is "console", which only prints codes to the log. Configure a real sender or set OTP_ENABLED=false.');
  }
  if (upstreams.length === 0 && !otpEnabled) {
    problems.push('No upstream providers are configured and OTP_ENABLED is false, so nobody could ever sign in.');
  }

  // The one optional piece of state in SAG, shared by single-use
  // authorisation codes and OTP send limits. Cloudflare KV is deliberately not
  // an option: it has no compare-and-set, so both controls would be races.
  const stateStore = {
    backend: oneOf(
      env,
      alias(env, ['STATE_STORE_BACKEND', 'REPLAY_STORE_BACKEND']),
      ['none', 'memory', 'cf-durable-object', 'dynamodb'],
      'none',
    ),
    // A deployment configured under the old names kept its namespace bound as
    // SAG_REPLAY, and renaming a binding is a redeploy rather than a restart,
    // so the old name stays the default for them.
    doBindingName: str(
      env,
      alias(env, ['STATE_STORE_DO_BINDING', 'REPLAY_STORE_DO_BINDING']),
      str(env, 'STATE_STORE_BACKEND') === undefined && str(env, 'REPLAY_STORE_BACKEND') !== undefined
        ? 'SAG_REPLAY'
        : 'SAG_STATE',
    ),
    table: str(env, alias(env, ['STATE_STORE_TABLE', 'REPLAY_STORE_TABLE'])),
    region: str(env, alias(env, ['STATE_STORE_REGION', 'REPLAY_STORE_REGION']), str(env, 'AWS_REGION')),
    endpoint: awsEndpoint(env, 'DYNAMODB'),
    // A cap, because an uncapped in-process map is a memory exhaustion bug
    // waiting for a busy afternoon.
    maxEntries: int(env, 'STATE_STORE_MAX_ENTRIES', 10000, { min: 100, max: 5000000 }),
    // Turns "nobody configured a backend" from a quiet fallback into a
    // startup error, the same shape as REQUIRE_POST_QUANTUM_SIGNING: a
    // deployment template, a copied environment file or a Terraform refactor
    // can drop STATE_STORE_BACKEND, and a missing variable looks exactly like
    // a deliberate choice not to have one unless something shouts.
    required: bool(env, 'REQUIRE_STATE_STORE', false),
  };
  if (stateStore.required && stateStore.backend === 'none') {
    throw new ConfigError(
      'REQUIRE_STATE_STORE is set but STATE_STORE_BACKEND is "none" (or unset). Configure a backend, or unset REQUIRE_STATE_STORE.',
    );
  }

  // Pulled out because the peer JWKS cache below defaults its grace period
  // off it, so it has to exist before the session section is built.
  const sessionMaxLifetimeSeconds = int(env, 'SESSION_MAX_LIFETIME', 7 * 86400, { min: 60, max: 365 * 86400 });

  const peerJwks = {
    urls: readPeerJwksUrls(env, devMode, warnings),
    // How often to refresh a peer that is answering. Matches the cache
    // header already on /jwks.json: long enough to spare a fetch per
    // token verification, short enough that a genuine key rotation is
    // picked up quickly.
    cacheTtlSeconds: int(env, 'PEER_JWKS_CACHE_TTL', 300, { min: 0, max: 86400 }),
    // How long to keep serving a peer's last-known keys after it stops
    // answering, before finally giving up on it. Generous on purpose: the
    // cost of keeping a stale-but-correct key around too long is a few more
    // bytes in the JWKS; the cost of dropping it too soon is a token that
    // instance signed while healthy failing verification somewhere, for a
    // reason that looks nothing like what actually happened. Defaults to
    // twice the longest a session can live, which is the longest duration
    // this deployment already has a concept of - see docs/multi-region.md.
    staleTtlSeconds: int(env, 'PEER_JWKS_STALE_TTL', 2 * sessionMaxLifetimeSeconds, { min: 0, max: 40 * 365 * 86400 }),
    timeoutMs: int(env, 'PEER_JWKS_TIMEOUT_MS', 4000, { min: 100, max: 20000 }),
    // Several peers each publishing a couple of post-quantum keys adds up:
    // an ML-DSA-44 public key alone is 1,312 bytes (docs/post-quantum.md).
    maxDocumentBytes: int(env, 'PEER_JWKS_MAX_BYTES', 64 * 1024, { min: 1024 }),
    cacheBackend: oneOf(env, 'PEER_JWKS_CACHE_BACKEND', ['memory', 'cf-kv', 'dynamodb'], 'memory'),
    cacheKvBindingName: str(env, 'PEER_JWKS_CACHE_KV_BINDING', 'SAG_PEER_JWKS'),
    cacheTable: str(env, 'PEER_JWKS_CACHE_TABLE'),
    cacheRegion: str(env, 'PEER_JWKS_CACHE_REGION', str(env, 'AWS_REGION')),
    cacheEndpoint: awsEndpoint(env, 'DYNAMODB'),
  };

  const config = {
    issuer,
    issuerOrigin: issuerUrl.origin,
    basePath: issuerUrl.pathname.replace(/\/+$/, ''),
    issuerDerived: derived,
    devMode,
    insecureTransport,
    secrets: secretsList,
    signing,
    stateStore,
    peerJwks,

    session: {
      scope: oneOf(env, 'SESSION_SCOPE', ['shared', 'rp'], 'shared'),
      cookieName: str(env, 'SESSION_COOKIE_NAME', 'sag_session'),
      idleTtlSeconds: int(env, 'SESSION_TTL', 12 * 3600, { min: 60, max: 90 * 86400 }),
      maxLifetimeSeconds: sessionMaxLifetimeSeconds,
      // When sessions are per relying party, a prompt=none request can still be
      // answered from the shared session if the operator allows it.
      promptNoneUsesSharedSession: bool(env, 'PROMPT_NONE_SHARED_SESSION', true),
      promptConsentMode: oneOf(env, 'PROMPT_CONSENT_MODE', ['continue', 'off'], 'continue'),
      // Whether a relying party asking to sign out gets an interstitial first.
      // "auto" asks only when the session is shared, so the person is told
      // that one application is signing them out of all of them. A relying
      // party can override this with CLIENT_<SLUG>_LOGOUT_CONFIRM.
      logoutConfirm: oneOf(env, 'LOGOUT_CONFIRM', ['auto', 'always', 'never'], 'auto'),
    },

    tokens: {
      authorizationCodeTtlSeconds: int(env, 'CODE_TTL', 60, { min: 10, max: 600 }),
      transactionTtlSeconds: int(env, 'TRANSACTION_TTL', 900, { min: 60, max: 3600 }),
      idTokenTtlSeconds: int(env, 'ID_TOKEN_TTL', 300, { min: 60, max: 3600 }),
      accessTokenTtlSeconds: int(env, 'ACCESS_TOKEN_TTL', 600, { min: 60, max: 86400 }),
      clockSkewSeconds: int(env, 'CLOCK_SKEW', 60, { min: 0, max: 300 }),
      // Single-use codes are enforced by the shared state store, which is
      // optional; see config.stateStore below and docs/state-and-limits.md.
    },

    subject: {
      // See docs/adr/0011-subject-derived-from-the-verified-address.md.
      type: oneOf(env, 'SUBJECT_TYPE', ['public', 'pairwise'], 'public'),
      // Both shapes need this, and it must never be rotated: a new salt gives
      // every person a new `sub` at every relying party.
      salt: str(env, 'SUBJECT_SALT'),
    },

    identity: {
      // Two spellings of one mailbox are one person. An operator who has a
      // reason to disagree - a deployment where tags are how people keep
      // separate accounts - turns it off, and a single relying party can
      // disagree on its own with CLIENT_<SLUG>_SANITISE_PLUS_EMAILS.
      sanitisePlusEmails: bool(env, 'SANITISE_PLUS_EMAILS', true),
    },

    clients: {
      static: staticClients,
      cimd: {
        // A URL client id makes SAG fetch its metadata, so accepting every
        // origin is an SSRF surface. It remains convenient on localhost, but a
        // real deployment must opt in and name the origins it trusts.
        enabled: bool(env, 'CLIENTS_CIMD_ENABLED', devMode),
        allowedDomains: list(env, 'CLIENTS_CIMD_ALLOWED_DOMAINS'),
        allowSubdomains: bool(env, 'CLIENTS_CIMD_ALLOW_SUBDOMAINS', true),
        cacheTtlSeconds: int(env, 'CLIENTS_CIMD_CACHE_TTL', 300, { min: 0, max: 86400 }),
        maxDocumentBytes: int(env, 'CLIENTS_CIMD_MAX_BYTES', 32 * 1024, { min: 1024 }),
      },
      opaque: {
        enabled: bool(env, 'CLIENTS_OPAQUE_ENABLED', true),
      },
      store: {
        // "file" is a directory of JSON records, provided by the Node adapter
        // as a binding, because the core has to bundle for a runtime with no
        // filesystem. See adapters/node/client-files.js.
        backend: oneOf(env, 'CLIENTS_STORE_BACKEND', ['none', 'cf-kv', 's3', 'file'], 'none'),
        directory: str(env, 'CLIENTS_STORE_DIR'),
        kvBindingName: str(env, 'CLIENTS_STORE_KV_BINDING', 'SAG_CLIENTS'),
        s3Bucket: str(env, 'CLIENTS_STORE_S3_BUCKET'),
        s3Region: str(env, 'CLIENTS_STORE_S3_REGION', str(env, 'AWS_REGION')),
        // Set for anything that is not S3 itself. Addressing then becomes
        // path style, because a bucket cannot be a subdomain of a hostname
        // that is not S3's.
        s3Endpoint: awsEndpoint(env, 'S3'),
        // A directory is already the prefix, so a file backend does not want
        // another one in front of every filename.
        prefix: str(env, 'CLIENTS_STORE_PREFIX', str(env, 'CLIENTS_STORE_BACKEND') === 'file' ? '' : 'clients/'),
        cacheTtlSeconds: int(env, 'CLIENTS_STORE_CACHE_TTL', 60, { min: 0, max: 3600 }),
      },
    },

    upstreams,

    otp: {
      enabled: otpEnabled,
      // Nine characters from a 30 symbol alphabet is about 2 x 10^13
      // combinations, which is what makes guessing hopeless even when the
      // attempt counter can be rolled back by resubmitting an older form.
      // Six digits would not be. Confusable characters (0, O, 1, I, L, U) are
      // not in the alphabet at all, so there is nothing to mistype.
      codeLength: codeLength(env, warnings),
      // Somebody who set OTP_DIGITS meant digits, so honour that unless they
      // have since said otherwise.
      codeAlphabet: oneOf(
        env,
        'OTP_CODE_ALPHABET',
        ['alphanumeric', 'numeric'],
        str(env, 'OTP_CODE_ALPHABET') === undefined && str(env, 'OTP_DIGITS') !== undefined
          ? 'numeric'
          : 'alphanumeric',
      ),
      ttlSeconds: int(env, 'OTP_TTL', 600, { min: 60, max: 3600 }),
      maxAttempts: int(env, 'OTP_MAX_ATTEMPTS', 5, { min: 1, max: 20 }),
      maxResends: int(env, 'OTP_MAX_RESENDS', 3, { min: 0, max: 10 }),
      // Enforced only when a state store is configured. Zero disables either.
      // The burst exists because a hard one-per-window rule and a ten minute
      // code lifetime between them mean somebody whose first code goes to spam
      // has no way forward at all; two sends per window keeps the mail bill
      // bounded and the person unstuck.
      sendWindowSeconds: int(env, alias(env, ['OTP_SEND_WINDOW', 'OTP_SEND_MIN_INTERVAL']), 600, { min: 0, max: 86400 }),
      sendBurst: int(env, 'OTP_SEND_BURST', 2, { min: 1, max: 50 }),
      sendDailyLimit: int(env, 'OTP_SEND_DAILY_LIMIT', 5, { min: 0, max: 1000 }),
      allowedDomains: list(env, 'OTP_ALLOWED_DOMAINS'),
      blockedDomains: list(env, 'OTP_BLOCKED_DOMAINS'),
    },

    signin: {
      // What to do with an address no upstream covers and OTP will not accept.
      // "silent" shows the code screen anyway, so the sign-in page cannot be
      // used to work out which domains a deployment is configured for.
      // "explain" tells the person, which is kinder and leaks the answer.
      unknownAddress: oneOf(env, 'SIGNIN_UNKNOWN_ADDRESS', ['silent', 'explain'], 'silent'),
    },

    email: {
      provider: emailProvider,
      from: str(env, 'EMAIL_FROM', devMode ? 'SAG <no-reply@localhost>' : undefined),
      replyTo: str(env, 'EMAIL_REPLY_TO'),
      subject: str(env, 'EMAIL_OTP_SUBJECT', 'Your sign-in code'),
      sesRegion: str(env, 'SES_REGION', str(env, 'AWS_REGION')),
      sesConfigurationSet: str(env, 'SES_CONFIGURATION_SET'),
      notifyApiKey: str(env, 'NOTIFY_API_KEY'),
      notifyTemplateId: str(env, 'NOTIFY_TEMPLATE_ID'),
      notifyBaseUrl: str(env, 'NOTIFY_BASE_URL', 'https://api.notifications.service.gov.uk'),
      mailchannelsEndpoint: str(env, 'MAILCHANNELS_ENDPOINT', 'https://api.mailchannels.net/tx/v1/send'),
      mailchannelsApiKey: str(env, 'MAILCHANNELS_API_KEY'),
      cloudflareBindingName: str(env, 'CLOUDFLARE_EMAIL_BINDING', 'SEND_EMAIL'),
      cloudflareDestination: str(env, 'CLOUDFLARE_EMAIL_DESTINATION'),
      smtpUrl: str(env, 'SMTP_URL'),
    },

    profile: {
      // Which OpenID Connect profile claims may be relayed from an upstream.
      // The default is everything an upstream commonly returns; a deployment
      // that does not want names or pictures crossing SAG at all narrows it.
      claims: list(env, 'PROFILE_CLAIMS', DEFAULT_PROFILE_CLAIMS).filter((c) => PROFILE_CLAIMS.includes(c)),
      // Pictures are separated out because they are the one profile claim that
      // makes the relying party's page fetch something from a third party.
      showPicture: bool(env, 'PROFILE_PICTURE', true),
      // Guessing a display name from the local part of an address, which is
      // the only source there is on the email code path. Off by default:
      // `name` is meant to be the person's name, and a guess dressed as one is
      // worse than no claim at all. See docs/profile-claims.md.
      nameFromEmail: oneOf(env, 'PROFILE_NAME_FROM_EMAIL', ['off', 'infer'], 'off'),
      // A generated initials avatar, as a data URI, for a person who has no
      // upstream picture. Self-contained on purpose: hashing the address and
      // sending it to an avatar service would hand a third party the fact of
      // every sign-in.
      avatarFallback: oneOf(env, 'PROFILE_AVATAR_FALLBACK', ['off', 'initials'], 'off'),
      // Whether the screens themselves show the name and picture SAG holds.
      showOnScreen: bool(env, 'PROFILE_SHOW_ON_SCREEN', true),
    },

    dns: {
      // Guessing which upstream serves a domain from its mail records, used
      // only when more than one upstream could take the address and the person
      // would otherwise be asked to choose. See docs/upstreams.md.
      hint: oneOf(env, 'SIGNIN_PROVIDER_HINT', ['off', 'order', 'select'], 'select'),
      // DNS-over-HTTPS, because Workers and Lambda have no resolver of their
      // own. The Node adapter supplies the platform resolver as a binding
      // instead, so a local deployment asks nobody.
      resolverUrl: str(env, 'DNS_RESOLVER_URL', 'https://cloudflare-dns.com/dns-query'),
      timeoutMs: int(env, 'DNS_TIMEOUT_MS', 1500, { min: 100, max: 10000 }),
      cacheTtlSeconds: int(env, 'DNS_CACHE_TTL', 3600, { min: 0, max: 86400 }),
      // An adapter can supply the platform resolver under this name, and then
      // no DNS query leaves the deployment. The Node adapter does.
      bindingName: str(env, 'DNS_BINDING', 'SAG_DNS'),
    },

    ui: {
      title: str(env, 'UI_TITLE', 'Sign in'),
      organisation: str(env, 'UI_ORG_NAME'),
      supportUrl: str(env, 'UI_SUPPORT_URL'),
      logoUrl: str(env, 'UI_LOGO_URL'),
      customCssSnippet: str(env, 'CUSTOM_CSS_SNIPPET'),
      customCssRemoteUrl: str(env, 'CUSTOM_CSS_REMOTE_URL'),
      locale: str(env, 'UI_LOCALE', 'en-GB'),
      // SAG is a RESOAuth product and the default pages say so. An operator
      // running it for their own organisation can put their own name and logo
      // in front with UI_WHITELABEL, which drops the product name from the
      // page but keeps the attribution in the footer.
      brandName: str(env, 'UI_BRAND_NAME', 'RESOAuth'),
      productName: str(env, 'UI_PRODUCT_NAME', 'Smart Access Gateway'),
      whitelabel: bool(env, 'UI_WHITELABEL', false),
      brandUrl: str(env, 'UI_BRAND_URL', 'https://resoauth.dev'),
      // Instance-wide legal links. A relying party can override them with
      // CLIENT_<SLUG>_TOS_URI and CLIENT_<SLUG>_POLICY_URI, or by publishing
      // tos_uri and policy_uri in its client metadata.
      termsUrl: str(env, 'UI_TERMS_URL'),
      privacyUrl: str(env, 'UI_PRIVACY_URL'),
    },

    acr: {
      supported: SUPPORTED_ACR_VALUES,
      defaultRequired: list(env, 'ACR_DEFAULT_REQUIRED'),
    },

    logLevel: oneOf(env, 'LOG_LEVEL', ['debug', 'info', 'warn', 'error', 'silent'], devMode ? 'debug' : 'info'),
    problems,
    warnings,
    // Warnings an operator must see and a stranger must not. Everything here
    // names a defence that is absent, which is exactly the sort of thing
    // /healthz stopped publishing; the start-up banner and the logs print
    // them, and nothing that answers a request does.
    internalWarnings,
  };

  if (stateStore.backend === 'memory' && !devMode) {
    internalWarnings.push(
      'The state store backend is "memory", which only prevents code reuse within a single instance and counts OTP sends per instance. Use cf-durable-object or dynamodb if more than one instance can serve a request.',
    );
  }
  if (stateStore.backend === 'none' && !devMode) {
    internalWarnings.push(
      'No state store is configured, so authorisation codes are single-use by convention only' +
        (otpEnabled ? ' and OTP send limits are not enforced' : '') +
        '. Set STATE_STORE_BACKEND, or put a platform rate limiting rule in front of this deployment. See docs/state-and-limits.md.',
    );
  }
  if (config.clients.cimd.enabled && !devMode && config.clients.cimd.allowedDomains.length === 0) {
    problems.push(
      'CLIENTS_CIMD_ENABLED is true but CLIENTS_CIMD_ALLOWED_DOMAINS is empty. Set it to the domains that may publish client metadata, or disable CLIENTS_CIMD_ENABLED.',
    );
  }
  if (!config.subject.salt) {
    if (devMode) {
      config.subject.salt = 'sag-development-only-subject-salt';
      warnings.push('SUBJECT_SALT is not set; using the development salt, so every `sub` this instance issues is guessable.');
    } else {
      problems.push(
        'SUBJECT_SALT is not set. Generate one with "openssl rand -base64 32" and never change it, because rotating it orphans every account at every relying party.',
      );
    }
  }
  // An endpoint override is how a local stack points at an emulator, so an
  // http one is expected in development and never anywhere else: SAG's signed
  // requests would still be unforgeable, but a KMS reply travelling in clear
  // is a signature anybody on the path can replace, and an S3 reply is the
  // relying party register itself.
  for (const [service, endpoint] of [
    ['KMS', signing.kmsEndpoint],
    ['DynamoDB', stateStore.endpoint],
    ['S3', config.clients.store.s3Endpoint],
  ]) {
    if (endpoint && endpoint.startsWith('http://') && !devMode) {
      problems.push('The ' + service + ' endpoint override is a plain http URL (' + endpoint + '). Calls to it must travel over TLS outside local development.');
    }
  }
  if (config.session.maxLifetimeSeconds < config.session.idleTtlSeconds) {
    problems.push('SESSION_MAX_LIFETIME must not be shorter than SESSION_TTL.');
  }
  if (config.ui.customCssRemoteUrl && !/^https:\/\//.test(config.ui.customCssRemoteUrl) && !devMode) {
    problems.push('CUSTOM_CSS_REMOTE_URL must be an https URL.');
  }

  return config;
}

/** Throw if the configuration is not safe to serve. */
export function assertUsable(config) {
  if (config.problems.length > 0) {
    throw new ConfigError(
      'SAG refused to start with this configuration:\n' + config.problems.map((p) => '  - ' + p).join('\n'),
    );
  }
  return config;
}
