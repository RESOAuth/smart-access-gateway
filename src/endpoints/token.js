// POST /token

import { json, readForm, single } from '../util/http.js';
import { OAuthError, invalidClient, invalidGrant } from '../util/errors.js';
import { readCredentials, authenticateClient, requireClientId } from '../oauth/clientauth.js';
import { redeemCode } from '../oauth/code.js';
import { idTokenClaims, signIdToken, issueAccessToken, tokenResponse } from '../oauth/tokens.js';

export async function handleToken(ctx) {
  const params = await readForm(ctx.request);
  const grantType = single(params, 'grant_type');

  if (grantType !== 'authorization_code') {
    throw new OAuthError(
      'unsupported_grant_type',
      grantType === 'refresh_token'
        ? 'Refresh tokens are not issued here. Re-run the authorization code flow; an existing session will usually answer it without any interaction.'
        : 'Only the authorization_code grant is supported.',
    );
  }

  const credentials = readCredentials(ctx.request, params);
  const clientId = requireClientId(credentials);
  const client = await ctx.resolveClient(clientId);
  if (!client) throw invalidClient('No client is registered with that client_id here.');
  await authenticateClient(ctx.config, client, credentials, ctx.stateStore);

  const code = single(params, 'code');
  if (!code) throw invalidGrant('The code parameter is missing.');

  const grant = await redeemCode(ctx.config, {
    code,
    clientId,
    redirectUri: single(params, 'redirect_uri'),
    codeVerifier: single(params, 'code_verifier'),
    replayStore: ctx.stateStore,
  });

  const accessToken = await issueAccessToken(ctx.config, grant);
  const claims = await idTokenClaims(ctx.config, {
    grant,
    audience: clientId,
    accessToken,
    nonce: grant.nonce,
  });
  const idToken = await signIdToken(ctx.config, ctx.signerSet, claims, grant.id_token_alg);

  ctx.log.info('tokens issued', {
    client_id: clientId,
    auth_method: client.tokenEndpointAuthMethod,
    alg: grant.id_token_alg || ctx.signerSet.primaryAlg,
  });

  return json(
    tokenResponse({
      accessToken,
      idToken,
      expiresIn: ctx.config.tokens.accessTokenTtlSeconds,
      scope: grant.scope || ['openid'],
    }),
  );
}
