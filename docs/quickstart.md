# Quickstart

Two ways to get an instance running, both with no configuration at all.

## Node, for development

```sh
npm run dev
```

There is nothing to install first: SAG has no runtime dependencies, and
`wrangler` is only needed if you deploy to Cloudflare. It starts on
`http://127.0.0.1:8787` with a development signing key, a development relying
party (`sag-dev-client`, loopback redirect URIs only) and email codes printed
to the console instead of sent.

Point any OpenID Connect client library at:

`http://127.0.0.1:8787/.well-known/openid-configuration`

The moment `SAG_ISSUER` names a real hostname, every development default
becomes a startup error rather than a quiet weakness: no signing key, no
master secret and a "console" mail provider all refuse to run.

## Docker, for something that keeps its state

```sh
docker compose up
```

On first start SAG generates a master secret, a subject salt and a signing key
into the `sag-data` volume and reads them back on every start afterwards, so
restarting the container does not sign everybody out. Codes are printed to the
log until a mail sender is configured:

```sh
docker compose logs -f sag
```

Configuration goes in `./config.env`, one `KEY=value` per line, and relying
parties go in `./data/clients/` as one JSON file each. See
[docker.md](docker.md) for the details and
[configuration.md](configuration.md) for what can go in it.

## The worked example relying party

```sh
npm run example      # in a second terminal, then open http://127.0.0.1:8788
```

About a hundred lines of plain Node with no dependencies, doing the whole
flow. It has buttons for the interesting cases - silent re-authentication,
forcing a fresh sign-in, demanding MFA, calling `/userinfo`, asking for a
post-quantum signature - and it verifies the `id_token` against the published
JWKS itself, so it doubles as the shortest honest answer to "what do I have to
implement?".

## Signing in

Enter any email address. With no upstream provider configured, SAG emails a
nine character code, and in development it prints it to the console and shows
it on the page. Enter it, and the flow completes back at the relying party.

To add Microsoft or Google, see [upstreams.md](upstreams.md). To add your own
application, see [relying-parties.md](relying-parties.md).

## Keys, when you are ready for a real deployment

```sh
npm run keygen                          # ES256 and a master secret
npm run keygen -- --alg ES256,ML-DSA-44 # and a post-quantum key alongside
npm run keygen -- --secret-only         # just the symmetric secrets
```

The output is copy-pasteable environment variables. Nothing is written to disk
unless you ask with `--out`, so a key cannot be left in a repository by
accident.
