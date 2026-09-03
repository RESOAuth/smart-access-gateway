// What SAG knows about each upstream provider out of the box.
//
// An operator should only have to supply a client id and secret, so everything
// else - endpoints, scopes, how to pin a tenant or a hosted domain - is
// derived from the provider name. Anything here can still be overridden by an
// UPSTREAM_..._AUTHORIZATION_ENDPOINT style variable for a provider that is
// almost, but not quite, one of these.

export const PROVIDERS = {
  microsoft: {
    label: 'Microsoft',
    scopes: ['openid', 'email', 'profile'],
    /**
     * Microsoft's issuer varies by tenant, so the discovery document is the
     * only reliable source for it. `common` accepts any tenant, which is what
     * an unrestricted deployment wants; a specific tenant id or domain pins it.
     */
    discoveryUrl: (u) =>
      'https://login.microsoftonline.com/' + encodeURIComponent(u.tenant || tenantFor(u)) + '/v2.0/.well-known/openid-configuration',
    /**
     * With `common`, the id_token issuer contains the caller's own tenant id,
     * so the value in the discovery document is a template. Comparing the
     * template literally would reject every real token.
     */
    issuerTemplate: true,
    extraAuthorizationParams: (u) => {
      const p = {};
      // domain_hint skips the "which account?" screen when we already know the
      // organisation, which is the whole point of a domain-specific upstream.
      if (!u.isCommon) p.domain_hint = u.domain;
      return p;
    },
    verifyClaims: (u, claims) => {
      const tid = String(claims.tid || '').toLowerCase();
      // The strongest bound available on a multi-tenant upstream, and the only
      // one that is about who is asserting rather than what they asserted:
      // `tid` is issued by Microsoft, not set in the directory. See ADR 0019.
      if (u.allowedTenants?.length && !u.allowedTenants.includes(tid)) {
        throw new Error('this Microsoft sign-in is from a tenant this upstream does not accept');
      }
      if (u.isCommon) {
        const verified = emailDomainVerified(claims);
        if (verified === false) {
          throw new Error('Microsoft reports that this address is not in a domain the tenant has verified');
        }
        // With no tenant list and no domain of its own, xms_edov is the only
        // thing standing between this upstream and any tenant administrator
        // asserting any address.
        if (!u.allowedTenants?.length && verified !== true) {
          throw new Error('this Microsoft upstream accepts any tenant, so it needs the xms_edov claim to trust an address');
        }
        return;
      }
      // A tenant-pinned upstream must not accept a guest from elsewhere.
      if (u.tenant && tid && u.tenant !== 'common' && u.tenant !== 'organizations' && tid !== u.tenant.toLowerCase()) {
        throw new Error('this Microsoft sign-in is from a different tenant');
      }
    },
  },

  google: {
    label: 'Google',
    scopes: ['openid', 'email', 'profile'],
    discoveryUrl: () => 'https://accounts.google.com/.well-known/openid-configuration',
    issuerTemplate: false,
    extraAuthorizationParams: (u) => {
      const p = {};
      // `hd` restricts the account chooser to one Workspace domain. It is a
      // hint only: the claim is checked again below.
      const hd = u.hd || (u.isCommon ? undefined : u.domain);
      if (hd) p.hd = hd;
      return p;
    },
    verifyClaims: (u, claims) => {
      const hd = u.hd || (u.isCommon ? undefined : u.domain);
      if (!hd) return;
      if (claims.hd !== hd) {
        throw new Error('this Google account is not in the expected hosted domain');
      }
    },
  },

  // A generic OpenID Connect provider. Everything must be configured.
  oidc: {
    label: 'Single sign-on',
    scopes: ['openid', 'email', 'profile'],
    discoveryUrl: (u) => (u.issuer ? u.issuer.replace(/\/+$/, '') + '/.well-known/openid-configuration' : undefined),
    issuerTemplate: false,
    extraAuthorizationParams: () => ({}),
    verifyClaims: () => {},
  },
};

/**
 * Whether Entra says the tenant has verified the domain of the `email` claim,
 * or undefined when it did not say. `xms_edov` is an optional claim, so it is
 * absent until the app registration asks for it, and Entra has emitted it both
 * as a JSON boolean and as a string.
 */
function emailDomainVerified(claims) {
  const raw = claims.xms_edov;
  if (typeof raw === 'boolean') return raw;
  if (raw === 'true' || raw === '1' || raw === 1) return true;
  if (raw === 'false' || raw === '0' || raw === 0) return false;
  return undefined;
}

function tenantFor(u) {
  // A domain-specific Microsoft upstream can address its tenant by domain,
  // which saves the operator having to look up a GUID.
  return u.isCommon ? 'common' : u.domain;
}

export function providerFor(name) {
  // eslint-disable-next-line security/detect-object-injection -- lookup in fixed PROVIDERS mapping with fallback
  return PROVIDERS[name] || PROVIDERS.oidc;
}

/** A human-readable name for a sign-in button. */
export function labelFor(upstream) {
  if (upstream.label) return upstream.label;
  const base = providerFor(upstream.provider).label;
  return upstream.isCommon ? base : base + ' (' + upstream.domain + ')';
}
