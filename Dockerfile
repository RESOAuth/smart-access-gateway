# SAG in a container.
#
# There is nothing to install: SAG has no runtime dependencies, so the image is
# the Node base plus about four hundred kilobytes of JavaScript and one tiny
# helper for dropping privileges. That is also why there is no build stage and
# no lockfile step.

FROM node:24-alpine

# su-exec is 20kB and does one thing: run a command as another user. See
# docker/entrypoint.sh for why that is needed rather than a fixed USER.
RUN apk add --no-cache su-exec

# Node 24 carries an OpenSSL new enough to offer ML-DSA, so a container can
# publish a post-quantum signing key where a Worker cannot yet. See
# docs/post-quantum.md.
ENV NODE_ENV=production \
    SAG_DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=8787

WORKDIR /srv/sag

COPY package.json ./
COPY src ./src
COPY adapters ./adapters
COPY tools ./tools
COPY docker ./docker

# The key material lives here, not in the image: an image that carried a
# signing key would put the identity of every deployment in a registry.
RUN mkdir -p /data /srv/sag && chown -R node:node /data /srv/sag

EXPOSE 8787

# /healthz answers only when configuration, keys and signing are all usable, so
# it is a real readiness check rather than a liveness ping.
#
# Podman builds OCI images by default and OCI has no HEALTHCHECK, so it prints
# a warning and ignores this. That is harmless: docker-compose.yml defines the
# same check at the container level, which Podman does honour. Build with
# `podman build --format docker` if you want it in the image itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# The entrypoint drops to whoever owns the data directory before running this.
ENTRYPOINT ["/srv/sag/docker/entrypoint.sh"]
CMD ["node", "tools/bootstrap.js"]
