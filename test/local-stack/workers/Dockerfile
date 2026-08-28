# SAG as a Cloudflare Worker, running on workerd.
#
# `wrangler dev` is not a simulation: it runs the same workerd that Cloudflare
# runs, with real Durable Objects backed by SQLite, so the state store in this
# instance is the actual implementation rather than a mock. Two Workers are
# started from one command - SAG and its private HSM - and the service binding
# between them is wired up locally, which is the only way to exercise the
# signing path a Cloudflare deployment uses.
#
# Debian rather than Alpine: workerd is built against glibc and will not start
# on musl.
#
# Built from the repository root.

FROM node:24-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df

WORKDIR /srv/sag

# Wrangler is the only dependency SAG has, and only for this. Installed before
# the source is copied so that editing a file does not reinstall it.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund --loglevel=error && npm cache clean --force

COPY src ./src
COPY adapters ./adapters
COPY test/local-stack/workers ./test/local-stack/workers

# No telemetry, no update check, and no interactive session: this runs with no
# terminal attached. HOME has to be writable because wrangler keeps its own
# state there.
ENV WRANGLER_SEND_METRICS=false \
    CI=1 \
    HOME=/tmp \
    PORT=8787

# Whatever wrangler persists - the Durable Object SQLite databases - belongs in
# a volume, not in the image.
RUN mkdir -p /srv/sag/.wrangler && chown -R node:node /srv/sag/.wrangler /srv/sag/test

USER node

CMD ["sh", "-c", "exec ./node_modules/.bin/wrangler dev \
  --config test/local-stack/workers/wrangler.dev.toml \
  --config test/local-stack/workers/wrangler.hsm.dev.toml \
  --ip 0.0.0.0 --port ${PORT}"]
