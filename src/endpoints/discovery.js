// Discovery and key publication.
//
// Three documents, because relying parties disagree about which to look for:
//
//   /.well-known/openid-configuration       OpenID Connect Discovery 1.0
//   /.well-known/oauth-authorization-server RFC 8414
//   /.well-known/oauth-protected-resource   RFC 9728, describing /userinfo
//
// They describe the same deployment, but they are not the same document. The
// OAuth one leaves out everything that is only meaningful to an OpenID Connect
// client - the claims, the prompts, the session endpoint - because advertising
// them to a plain OAuth client says nothing it can act on.
//
// Everything here is derived from what this instance is actually configured to
// do. A deployment with no upstream providers must not advertise a federated
// `acr`, one that cannot sign ML-DSA must not offer it, and one that will never
// see a profile claim must not list one: a relying party that believes a
// discovery document and then asks for something unreachable fails at the worst
// possible moment, which is mid-sign-in.

import { cachedJson } from '../util/http.js';
import { ACR } from '../acr.js';
import { PRIVATE_KEY_JWT_ALGS } from '../oauth/clientauth.js';
import { clientCapabilities } from '../clients/index.js';
import { reachableProfileClaims } from '../profile.js';
import { mergeJwks } from '../keys/peers.js';

/** The claims every id_token from this deployment carries. */
const CORE_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'sid'];

/**
 * Which authentication contexts this instance could actually assert.
 *
 * A relying party uses this to decide whether demanding one is worth doing, so
 * naming a context nothing here can produce is worse than saying nothing.
 */
function acrValuesFor(config) {
  const values = [];
  if (config.otp.enabled) values.push(ACR.OTP);
  if (config.upstreams.length > 0) values.push(ACR.FEDERATED, ACR.FEDERATED_MFA);
  return values;
}

/** Which `sub` shapes a relying party here might be given. */
function subjectTypesFor(config) {
  const types = new Set([config.subject.type]);
  for (const client of config.clients.static) if (client.subjectType) types.add(client.subjectType);
  // A store or a metadata document can name a subject type we have not seen
  // yet, so both remain possible answers as long as either is switched on.
  if (config.clients.store.backend !== 'none' || config.clients.cimd.enabled) {
    types.add('pairwise');
    types.add('public');
  }
  return [...types];
}

/**
 * Which `prompt` values do something here.
 *
 * `consent` is only honest when the instance will actually show the confirm
 * screen; with PROMPT_CONSENT_MODE=off it is accepted and ignored, so listing
 * it would promise a screen that never appears.
 */
function promptValuesFor(config) {
  const values = ['none', 'login', 'select_account'];
  if (config.session.promptConsentMode !== 'off') values.push('consent');
  return values;
}

/** The scopes that can return something on this deployment. */
function scopesFor(config, profileClaims) {
  const scopes = ['openid', 'email'];
  if (profileClaims.length > 0) scopes.push('profile');
  return scopes;
}

/** Metadata common to the OpenID Connect and the OAuth 2.1 document. */
function commonMetadata(ctx) {
  const { config, signerSet } = ctx;
  const at = (p) => config.issuer + p;
  const capabilities = clientCapabilities(config);

  const document = {
    issuer: config.issuer,
    authorization_endpoint: at('/authorize'),
    token_endpoint: at('/token'),
    // The well-known path is the canonical one; /jwks.json stays served for
    // anything already configured against it.
    jwks_uri: at('/.well-known/jwks.json'),

    scopes_supported: scopesFor(config, reachableProfileClaims(config)),
    response_types_supported: ['code'],
    response_modes_supported: ['query', 'form_post'],
    grant_types_supported: ['authorization_code'],

    // Only what this runtime can really do. A deployment on a runtime without
    // ML-DSA must not advertise it, or relying parties will ask and fail.
    id_token_signing_alg_values_supported: signerSet.algs,
    token_endpoint_auth_methods_supported: capabilities.authMethods,

    code_challenge_methods_supported: ['S256'],

    acr_values_supported: acrValuesFor(config),
    ui_locales_supported: [config.ui.locale],

    // RFC 9207. A relying party that checks this cannot be fooled into
    // accepting a code from a different identity provider.
    authorization_response_iss_parameter_supported: true,
  };

  // Only meaningful when a client could actually use the method.
  if (capabilities.authMethods.includes('private_key_jwt')) {
    document.token_endpoint_auth_signing_alg_values_supported = PRIVATE_KEY_JWT_ALGS;
  }
  if (config.ui.termsUrl) document.op_tos_uri = config.ui.termsUrl;
  if (config.ui.privacyUrl) document.op_policy_uri = config.ui.privacyUrl;

  // Not part of any specification, so namespaced: PKCE is mandatory here
  // rather than negotiable, which lets a client library fail at configuration
  // time instead of mid-flow, and a hint at where the post-quantum migration
  // stands on this instance.
  document['urn:sag:require_pkce'] = true;
  document['urn:sag:post_quantum_signing_supported'] = signerSet.hasPostQuantum;
  document['urn:sag:post_quantum_algs'] = signerSet.postQuantumAlgs;
  document['urn:sag:client_registration'] = {
    cimd: capabilities.cimd,
    static: capabilities.static > 0,
    store: capabilities.store,
  };

  return document;
}

/** The OpenID Connect Discovery 1.0 document. */
export function openidConfiguration(ctx) {
  const { config } = ctx;
  const at = (p) => config.issuer + p;
  const profileClaims = reachableProfileClaims(config);

  return {
    ...commonMetadata(ctx),
    userinfo_endpoint: at('/userinfo'),
    end_session_endpoint: at('/logout'),

    subject_types_supported: subjectTypesFor(config),

    claims_supported: [...CORE_CLAIMS, 'email', 'email_verified', ...profileClaims],
    claim_types_supported: ['normal'],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,

    prompt_values_supported: promptValuesFor(config),
    display_values_supported: ['page'],

    // Stated rather than omitted: a relying party that needs a logout it can
    // rely on should know now that this is not it. Sessions live in a cookie,
    // so there is nobody to notify.
    frontchannel_logout_supported: false,
    backchannel_logout_supported: false,
  };
}

/** The RFC 8414 authorization server metadata document. */
export function authorizationServerMetadata(ctx) {
  const { config } = ctx;
  return {
    ...commonMetadata(ctx),
    // RFC 9126. Stated so a client that would otherwise probe for it does not.
    require_pushed_authorization_requests: false,
    // RFC 9728: where to read about the one resource this server protects.
    'urn:sag:protected_resources': [config.issuer + '/userinfo'],
  };
}

/**
 * The RFC 9728 protected resource metadata for /userinfo.
 *
 * This is the half of the picture the authorization server metadata cannot
 * give: a client holding an access token needs to know which server issued it
 * and how to present it. /userinfo also names this document in its
 * WWW-Authenticate challenge, which is the discovery path the RFC intends.
 */
export function protectedResourceMetadata(ctx) {
  const { config } = ctx;
  return {
    resource: config.issuer + '/userinfo',
    authorization_servers: [config.issuer],
    scopes_supported: scopesFor(config, reachableProfileClaims(config)),
    // The query-string form is deliberately not accepted: it would put a
    // credential in logs and Referer headers.
    bearer_methods_supported: ['header', 'body'],
    // Access tokens are sealed rather than signed, and are only ever opened
    // here, so there is no signing algorithm for a client to verify against.
    resource_signing_alg_values_supported: [],
  };
}

export async function handleDiscovery(ctx) {
  return cachedJson(openidConfiguration(ctx), 300);
}

export async function handleAuthorizationServerMetadata(ctx) {
  return cachedJson(authorizationServerMetadata(ctx), 300);
}

export async function handleProtectedResourceMetadata(ctx) {
  return cachedJson(protectedResourceMetadata(ctx), 300);
}

export async function handleJwks(ctx) {
  const local = await ctx.signerSet.jwks();
  // A deployment with no peers configured publishes exactly what it always
  // has: only its own keys. See docs/multi-region.md for what a peer is and
  // what listing one means.
  const keys = ctx.peerJwks ? mergeJwks(local.keys, await ctx.peerJwks.keys({ log: ctx.log })) : local.keys;
  // A short cache. Long enough to spare the HSM or KMS a call per token
  // verification, short enough that adding a key is picked up quickly.
  return cachedJson({ keys }, 300);
}

/** Kept for callers that want the OpenID Connect document by its old name. */
export const metadataDocument = async (ctx) => openidConfiguration(ctx);
