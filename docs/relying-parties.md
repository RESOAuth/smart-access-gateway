# Adding relying parties

A relying party is an application that sends people to SAG to sign in. There
are four ways to describe one, checked in this order.

## 1. Environment variables, for a handful

```sh
CLIENT_LEDGER_ID=ledger
CLIENT_LEDGER_REDIRECT_URIS=https://ledger.example.com/auth/callback
CLIENT_LEDGER_SECRET=...                 # omit for a public client
CLIENT_LEDGER_NAME=Ledger
```

`LEDGER` is a slug of your choosing; it only groups the variables together and
never appears anywhere a person can see. Every field:

| Variable | Meaning |
| --- | --- |
| `CLIENT_<SLUG>_ID` | The `client_id` the application sends |
| `CLIENT_<SLUG>_REDIRECT_URIS` | Comma or space separated. Matched exactly |
| `CLIENT_<SLUG>_SECRET` | Present means confidential, absent means public |
| `CLIENT_<SLUG>_NAME` | Shown to the person: "Continue to Ledger" |
| `CLIENT_<SLUG>_POST_LOGOUT_REDIRECT_URIS` | Where sign-out may return to |
| `CLIENT_<SLUG>_JWKS` / `_JWKS_URI` | For `private_key_jwt` authentication |
| `CLIENT_<SLUG>_AUTH_METHOD` | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt` |
| `CLIENT_<SLUG>_SCOPES` | Restrict which scopes this client may ask for |
| `CLIENT_<SLUG>_ACR_VALUES` | A floor, applied whether or not the client asks |
| `CLIENT_<SLUG>_ID_TOKEN_SIGNED_RESPONSE_ALG` | Which algorithm to sign its `id_token` with |
| `CLIENT_<SLUG>_SESSION_SCOPE` | `shared` or `rp`, overriding the instance |
| `CLIENT_<SLUG>_LOGOUT_CONFIRM` | `auto`, `always` or `never` |
| `CLIENT_<SLUG>_TOS_URI` / `_POLICY_URI` | Legal links shown on the sign-in pages |
| `CLIENT_<SLUG>_SANITISE_PLUS_EMAILS` | Whether `jamie+shop@` is `jamie@` to this one client. Unset inherits `SANITISE_PLUS_EMAILS` |
| `CLIENT_<SLUG>_REQUIRE_PKCE` | Defaults to true, and should stay true |

Redirect URIs are matched exactly. OAuth 2.1 removed prefix and wildcard
matching because every variant of it has been used to smuggle a code to
somebody else's page. The only concession is the loopback port, which RFC 8252
requires to be ignored because a native application cannot know which port it
will be given.

## 2. A client store, for many

JSON documents keyed by client id, in a directory, a Cloudflare KV namespace
or an S3 bucket:

```sh
CLIENTS_STORE_BACKEND=file         # a directory of files, Node and containers
CLIENTS_STORE_DIR=/data/clients

CLIENTS_STORE_BACKEND=cf-kv        # Cloudflare
CLIENTS_STORE_KV_BINDING=SAG_CLIENTS

CLIENTS_STORE_BACKEND=s3           # AWS
CLIENTS_STORE_S3_BUCKET=example-sag-clients
CLIENTS_STORE_S3_REGION=eu-west-2
CLIENTS_STORE_PREFIX=clients/
```

The `file` backend is the one to use on a container or a single VM: one
`<client id>.json` per relying party in a directory somebody can edit, re-read
as it changes. It needs a filesystem, so it is available on Node and Lambda
and not on Workers, where KV is the equivalent.

A record looks like this:

```json
{
  "client_name": "Ledger",
  "redirect_uris": ["https://ledger.example.com/auth/callback"],
  "client_secret_digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "acr_values": ["urn:sag:acr:federated-mfa"],
  "subject_type": "pairwise",
  "sector_identifier": "example.com",
  "sanitise_plus_emails": false,
  "tos_uri": "https://ledger.example.com/terms"
}
```

`subject_type`, `sector_identifier` and `sanitise_plus_emails` override the
instance for this one relying party; leaving a field out inherits, which is not
the same as setting it to `false`. What they mean is in
[ADR 0011](adr/0011-subject-derived-from-the-verified-address.md).

Secrets are stored as `sha256:` digests, never in the clear - `npm run
generate-client-secret` mints a high-entropy secret and its digest together -
and the store is read-only from SAG's point of view: managing the records is
somebody else's problem, which keeps the identity path free of a write path
to break.

## 3. Client ID Metadata Documents, for no registration at all

The client id is an `https` URL that serves the client's own metadata. Nothing
has to be registered anywhere: the document's URL *is* the identity, so only
somebody controlling that origin can change what the client claims to be.

```sh
CLIENTS_CIMD_ENABLED=true
CLIENTS_CIMD_ALLOWED_DOMAINS=example.com
CLIENTS_CIMD_ALLOW_SUBDOMAINS=true
CLIENTS_CIMD_CACHE_TTL=300
CLIENTS_CIMD_MAX_BYTES=32768
```

SAG requires at least one well-formed redirect URI. The allow list is an
explicit trust boundary: a permitted domain may declare its own redirect URIs,
including loopback URIs for native applications. SAG refuses redirects while
fetching the document and caps its size. These rules limit both where SAG will
fetch metadata from and how much of it it will read.

Such a client is public by construction - the document is readable by anybody,
so it can hold no secret - which is why PKCE is required of it regardless of
what the document says. Publishing a `jwks` or `jwks_uri` instead is how one
authenticates at the token endpoint, and the only way it stops being public.

A worked one, serving its own document and signing in with it, is in
[examples/relying-party](../examples/relying-party/server.js):

```sh
EXAMPLE_USE_CIMD_AND_PUBLIC_CLIENT=1 npm run example
```

It runs as the fourth application in
[test/local-stack/](../test/local-stack/README.md), which is also the shortest
demonstration of the one practical constraint: the client id has to resolve to
the same place for the browser following a redirect and for SAG fetching the
document.

## 4. Opaque clients

A GUID for a client id, with a hashed secret or a JWKS, held in the store.
This is the shape for machine-registered relying parties. Set
`CLIENTS_OPAQUE_ENABLED=false` to require every relying party to be either
statically configured or self-describing.

## Which authentication method to use

- **Public client** (a single page app, a mobile app): no secret, PKCE
  mandatory. SAG will not accept a public client without PKCE.
- **Confidential client** with a secret: `client_secret_basic` or
  `client_secret_post`.
- **Confidential client** with a key: `private_key_jwt`, which never sends a
  shared secret over the wire at all and is the right answer for anything
  long-lived. The assertion's audience, lifetime and signature are all
  checked, and a reused assertion is refused.

## Demanding a stronger sign-in

A relying party can ask for an authentication context, and SAG will refuse
rather than quietly answering with something weaker:

```
acr_values=urn:sag:acr:federated-mfa
```

`CLIENT_<SLUG>_ACR_VALUES` sets a floor that applies whether or not the client
asks, which is how an enterprise deployment stops one application from being
the weak way in. See the `acr` and `amr` values in
[configuration.md](configuration.md).
