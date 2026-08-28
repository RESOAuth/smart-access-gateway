# Running SAG in a container

```sh
docker compose up          # or: podman-compose up -d
```

That is the whole setup. Everything below is what happens next.

## Where things live

Everything is a file you can open:

| | |
| --- | --- |
| `./config.env` | Settings, as `KEY=value` lines. Read on the host by compose and handed to the container as environment variables |
| `./data/clients/` | One JSON file per relying party. See [the README in that directory](../data/clients/README.md) |
| `./data/sag.env` | The generated master secret, subject salt and signing key. Written once, mode 600, never rewritten |

### How the ownership works

A bind-mounted directory is the awkward part of running a container as a
non-root user, and it is awkward in opposite directions depending on the
runtime. Under Docker, `./data` belongs to you and the container sees your
uid. Under rootless Podman, you are mapped to *root* inside the container, so
`./data` appears to belong to root and the image's own user can write nothing -
which is where `EACCES: permission denied, open '/data/sag.env'` comes from.

The container therefore reads who owns the data directory and becomes them
before starting SAG: `docker/entrypoint.sh`. Under Docker that drops from root
to your uid, so the files it writes stay editable on the host. Under rootless
Podman staying root *is* being you. Nothing has to be configured either way,
and nothing gains a privilege it did not already have.

`./data` is committed to the repository as an empty directory on purpose. If a
runtime has to create a bind-mount source itself it creates it as root, which
is the one case the entrypoint cannot fix from inside.

## Configuring it

`./config.env` is committed with comments only. One `KEY=value` per line:

```sh
SAG_ISSUER=https://id.example.com
EMAIL_PROVIDER=smtp
SMTP_URL=smtps://user:pass@smtp.example.com:465
EMAIL_FROM=Sign in <no-reply@id.example.com>

UPSTREAM_MICROSOFT_COMMON_CLIENT_ID=common:00000000-1111-2222-3333-444444444444
UPSTREAM_MICROSOFT_COMMON_CLIENT_SECRET=...

CLIENT_LEDGER_ID=ledger
CLIENT_LEDGER_REDIRECT_URIS=https://ledger.example.com/auth/callback
```

Restart to apply: `docker compose restart sag`. Every variable is in
[configuration.md](configuration.md).

If you fork this repository, keep secrets out of a tracked file. Either use
your platform's secret store, or `git update-index --skip-worktree config.env`
so your copy stops being tracked.

## Relying parties

`config.env` points the client store at the directory:

```sh
CLIENTS_STORE_BACKEND=file
CLIENTS_STORE_DIR=/data/clients
```

One file per relying party, named after its client id, so `ledger` is
`./data/clients/ledger.json`:

```json
{
  "client_name": "Ledger",
  "redirect_uris": ["https://ledger.example.com/auth/callback"],
  "client_secret_digest": "sha256:5a9006...",
  "tos_uri": "https://ledger.example.com/terms"
}
```

Records are re-read as they change, cached for `CLIENTS_STORE_CACHE_TTL`
seconds (60 by default), so an edit takes effect without a restart. A secret
is stored as a digest and never in the clear - `npm run
generate-client-secret` mints one along with its digest. A file that is not
valid JSON, or that has no `redirect_uris`, is one missing client rather than
an outage for everybody else.

`./data/clients/README.md` lists every field a record can carry, and the
start-up banner says how many files it can actually see, because a typo in the
path otherwise reads as "no clients configured".

## The key material

`./data/sag.env` is written once, with mode 600, and never rewritten. It is
the identity of the deployment: anyone holding it can impersonate it, and
deleting it starts a new identity, which signs everybody out and invalidates
every token the instance has issued. Back it up the way you would back up a
TLS private key.

Anything you set in `config.env` wins over the generated file, so moving to a
real secret manager later means setting `SAG_SECRET` and
`SIGNING_PRIVATE_JWK` there and leaving `sag.env` alone.

## Putting it behind TLS

SAG must be told what it is. Set the public `https` URL in `config.env`:

```sh
SAG_ISSUER=https://id.example.com
```

Once the issuer is not a development hostname, SAG refuses to start with a
development secret, an ephemeral signing key or the console mail provider. An
`http` issuer is refused too, because a session cookie and an authorisation
code must not travel in clear.

## State, with one container and with several

`config.env` sets `STATE_STORE_BACKEND=memory`, which is genuinely atomic here
because a container is one process. That makes authorisation codes single-use
and enforces the OTP send limits, and it is capped so it cannot be made to
exhaust the container.

Behind a load balancer with more than one container it is not enough: each
container counts its own. Use DynamoDB, or run the Cloudflare deployment
instead. See [state-and-limits.md](state-and-limits.md).

## Pre-built images

CI publishes images to GHCR, so a fork or a production deployment does not
have to build one: `ghcr.io/resoauth/sag:latest` tracks the latest release,
and `ghcr.io/resoauth/sag:bleeding-edge` tracks `main` after every push that
touches something buildable. Point `docker-compose.yml`'s `image:` at one of
these instead of `build: .` to use it.

## Upgrading

```sh
git pull && docker compose up --build -d
```

`./data` is untouched by a rebuild, so sessions and tokens survive.

## When it does not come up

```sh
podman ps -a --filter name=sag     # Up, or Restarting?
podman logs sag | tail -30         # the start-up banner, or the crash
podman port sag                    # what the publish actually mapped
curl -sv http://127.0.0.1:8787/healthz
```

Three things account for nearly all of it:

- **A container left over from a failed run.** `restart: unless-stopped` keeps
  a broken container cycling, and compose reuses an existing container rather
  than recreating it, so a fix to this file changes nothing until you run
  `podman-compose down` (or `docker compose down`) first. Follow it with
  `up -d --build` so the image is rebuilt too.
- **A stale image.** `build:` only builds when the image is missing, so
  `--build` is what picks up a change to the Dockerfile or the source.
- **`localhost` resolving to `::1`.** Rootless Podman publishes on IPv4, so a
  browser that tries IPv6 first can look like it is hanging. `curl` against
  `127.0.0.1` tells you in one line whether that is what you are seeing.
- **A browser outside the machine running the container.** See below.

A request that hangs rather than being refused usually means the port is
published but nothing inside the container is listening on it - a crash loop,
or a server bound to `127.0.0.1` inside the container rather than `0.0.0.0`.
The compose file sets `HOST=0.0.0.0` explicitly for that reason.

## ChromeOS, and anywhere else the browser is not on the same host

On ChromeOS the Linux container is a separate VM. Chrome runs on ChromeOS
itself, so `http://localhost:8787` in the browser is ChromeOS's own localhost
and nothing is listening there, however well the container is running. `curl`
from the Linux terminal works, which makes it look like a browser problem.

Two ways round it:

`http://penguin.linux.test:8787/healthz`

ChromeOS resolves `<container>.linux.test` to the Linux VM, so this reaches
SAG with no configuration at all. `penguin` is the default container name;
`hostname` tells you yours. SAG treats `.linux.test` as a development hostname
for exactly this reason, so it does not decide it is in production and refuse
to start over an `http` issuer.

Or forward the port, so `localhost` works as it does everywhere else: ChromeOS
**Settings** > **Advanced** > **Developers** > **Linux development
environment** > **Port forwarding**, and add 8787.

The same applies to any setup where the browser is not on the host running the
container - a remote server, WSL in some configurations, a VM. Reach it by the
host's name or address, and set `SAG_ISSUER` to whatever that name is once it
is more than a local experiment.

## Health

```sh
curl -s http://localhost:8787/healthz | jq
```

It answers only when configuration, keys and signing are all usable, so the
compose healthcheck is a real readiness check rather than a liveness ping -
`/alive` is the liveness ping, if something in front of the container wants
one. [operations.md](operations.md) explains how to read both.
