# Relying party records

One JSON file per relying party, named after its client id: a client id of
`ledger` is `ledger.json`. SAG re-reads them as they change, cached for
`CLIENTS_STORE_CACHE_TTL` seconds (60 by default), so an edit takes effect
without a restart.

Turn this on in `config.env`, which is where the compose file already points
it:

```sh
CLIENTS_STORE_BACKEND=file
CLIENTS_STORE_DIR=/data/clients
```

A minimal public client, the kind a single page application or a mobile app
uses:

```json
{
  "client_name": "Ledger",
  "redirect_uris": ["https://ledger.example.com/auth/callback"],
  "post_logout_redirect_uris": ["https://ledger.example.com/"]
}
```

A confidential client, with the secret stored as a digest so that reading this
file is not enough to impersonate the application. Generate a secret and its
digest with `npm run generate-client-secret`, then give the secret itself to
the relying party:

```json
{
  "client_name": "Ledger",
  "redirect_uris": ["https://ledger.example.com/auth/callback"],
  "client_secret_digest": "sha256:5a90063288c04e4df59164f25bacb191f42f8f7e11b127030cb01fffd22af956",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

Every field a record may carry:

| Field | Meaning |
| --- | --- |
| `client_name` | Shown to the person: "Continue to Ledger" |
| `redirect_uris` | Required. Matched exactly |
| `post_logout_redirect_uris` | Where sign-out may return to |
| `client_secret_digest` | `sha256:<hex>`, of a secret from `npm run generate-client-secret`. Never the secret itself |
| `jwks` / `jwks_uri` | For `private_key_jwt` authentication |
| `token_endpoint_auth_method` | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt` |
| `scope` | Restrict which scopes this client may ask for |
| `acr_values` | A floor, applied whether or not the client asks |
| `id_token_signed_response_alg` | Which algorithm signs its `id_token` |
| `session_scope` | `shared` or `rp`, overriding the instance |
| `logout_confirm` | `auto`, `always` or `never` |
| `tos_uri`, `policy_uri` | Legal links shown on the sign-in pages |
| `require_pkce` | Defaults to true, and should stay true |

A file that is not valid JSON, or that has no `redirect_uris`, is treated as
no such client rather than as a reason to stop serving everybody else.
