// A stand-in identity provider.
//
// The federation path is the half of SAG that talks to somebody else, and it
// cannot be tested against Microsoft or Google in CI. This serves the same
// three things a real provider does - a discovery document, a JWKS, and a token
// endpoint that returns a genuinely signed id_token - so the code under test
// does real discovery, real signature verification and real claim validation.
// Only the network is fake.

import { publicPartOf, jwkThumbprint, signCompact, importPrivateJwk } from '../src/crypto/jose.js';
import { nowSeconds } from '../src/util/bytes.js';

/**
 * @param {object} [opts]
 * @param {string} [opts.origin]  Where the stub appears to live
 * @param {string} [opts.issuer]  Overrides the issuer, for template testing
 */
export async function createStubProvider(opts = {}) {
  const origin = opts.origin || 'https://stub-idp.test';
  const issuer = opts.issuer || origin;
  const alg = 'ES256';

  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const privateJwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), alg };
  const kid = await jwkThumbprint(privateJwk);
  const publicJwk = publicPartOf({ ...privateJwk, kid });
  const signingKey = await importPrivateJwk(privateJwk, alg);

  const metadata = {
    issuer,
    authorization_endpoint: origin + '/oauth2/authorize',
    token_endpoint: origin + '/oauth2/token',
    jwks_uri: origin + '/oauth2/keys',
    ...opts.metadata,
  };

  const state = {
    /** Claims the next id_token will carry, on top of the required ones. */
    claims: {},
    /** Set to make the token endpoint fail. */
    tokenError: undefined,
    /** Requests the stub received, for assertions. */
    tokenRequests: [],
    discoveryCount: 0,
  };

  /** Mint an id_token as this provider would. */
  async function mintIdToken({ audience, nonce, claims = {} }) {
    const now = nowSeconds();
    const payload = {
      iss: issuer,
      aud: audience,
      sub: 'upstream-subject-1',
      iat: now,
      exp: now + 300,
      nonce,
      ...state.claims,
      ...claims,
    };
    return signCompact(alg, signingKey, { typ: 'JWT', kid }, payload);
  }

  /**
   * A fetch replacement. Anything not addressed to this provider is refused
   * loudly, so a test can never accidentally reach the real internet.
   */
  function fetchStub(input, init = {}) {
    const url = typeof input === 'string' ? input : input.url;
    const jsonResponse = (body, status = 200) =>
      Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));

    if (url.startsWith(origin + '/.well-known/openid-configuration') || url === opts.discoveryUrl) {
      state.discoveryCount++;
      return jsonResponse(metadata);
    }
    if (url === metadata.jwks_uri) return jsonResponse({ keys: [publicJwk] });
    if (url === metadata.token_endpoint) {
      const body = new URLSearchParams(typeof init.body === 'string' ? init.body : '');
      state.tokenRequests.push(Object.fromEntries(body));
      if (state.tokenError) return jsonResponse({ error: state.tokenError }, 400);
      return jsonResponse({
        access_token: 'upstream-access-token',
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: state.pendingIdToken,
      });
    }
    return Promise.reject(new Error('stub provider received an unexpected request: ' + url));
  }

  return {
    origin,
    issuer,
    metadata,
    publicJwk,
    state,
    mintIdToken,
    fetchStub,
    /** Prepare the id_token the next token exchange will return. */
    async expect({ audience, nonce, claims }) {
      state.pendingIdToken = await mintIdToken({ audience, nonce, claims });
      return state.pendingIdToken;
    },
    /** Install the stub and return a function that restores real fetch. */
    install() {
      const real = globalThis.fetch;
      globalThis.fetch = fetchStub;
      return () => {
        globalThis.fetch = real;
      };
    },
  };
}

/**
 * Read the parameters SAG sent to the upstream out of a redirect Location.
 * The nonce in particular has to come from here, because it is generated
 * inside the flow and sealed into the state.
 */
export function readUpstreamRedirect(response) {
  const location = response.headers.get('location');
  if (!location) throw new Error('expected a redirect to the upstream, got status ' + response.status);
  const url = new URL(location);
  return {
    url,
    params: Object.fromEntries(url.searchParams),
    state: url.searchParams.get('state'),
    nonce: url.searchParams.get('nonce'),
  };
}
