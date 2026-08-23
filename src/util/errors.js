/** An error that maps to an OAuth 2.1 / OIDC error response. */
export class OAuthError extends Error {
  /**
   * @param {string} code       OAuth error code, e.g. 'invalid_request'
   * @param {string} description Human-readable, safe to show
   * @param {object} [opts]
   * @param {number} [opts.status]      HTTP status for direct responses
   * @param {boolean} [opts.redirect]   May be relayed to the RP redirect_uri
   * @param {string} [opts.uri]         error_uri
   */
  constructor(code, description, opts = {}) {
    super(`${code}: ${description}`);
    this.name = 'OAuthError';
    this.code = code;
    this.description = description;
    this.status = opts.status ?? 400;
    this.redirectable = opts.redirect ?? false;
    this.uri = opts.uri;
  }
  toJSON() {
    const o = { error: this.code, error_description: this.description };
    if (this.uri) o.error_uri = this.uri;
    return o;
  }
}

/** A non-OAuth failure to render as an HTML error page. */
export class UserFacingError extends Error {
  constructor(title, detail, status = 400) {
    super(`${title}: ${detail}`);
    this.name = 'UserFacingError';
    this.title = title;
    this.detail = detail;
    this.status = status;
  }
}

export const invalidRequest = (d) => new OAuthError('invalid_request', d, { redirect: true });
export const invalidClient = (d) => new OAuthError('invalid_client', d, { status: 401 });
export const invalidGrant = (d) => new OAuthError('invalid_grant', d);
export const serverError = (d) => new OAuthError('server_error', d, { status: 500, redirect: true });
export const accessDenied = (d) => new OAuthError('access_denied', d, { redirect: true });
export const loginRequired = (d) => new OAuthError('login_required', d, { redirect: true });
export const interactionRequired = (d) => new OAuthError('interaction_required', d, { redirect: true });
export const unmetAcr = (d) => new OAuthError('unmet_authentication_requirements', d, { redirect: true });
