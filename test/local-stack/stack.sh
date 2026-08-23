#!/usr/bin/env bash
# Drive the local stack with whichever compose is installed.
#
#   ./stack.sh up            build, start, wait for every instance, print the map
#
# `up` always rebuilds and recreates. It is the command you run after editing
# SAG, so a container left running on the old image would be a lie - and it
# makes `up` idempotent, which is worth more here than the minute it costs.
#   ./stack.sh verify        sign in against all three instances, headless
#   ./stack.sh logs sag-node follow one container's log
#   ./stack.sh ps
#   ./stack.sh restart sag-node
#   ./stack.sh down          stop everything and remove the volumes
#
# Anything else is passed straight through to compose, so `./stack.sh exec
# sag-node sh` works as you would expect.
#
# Waiting is done here rather than left to compose, because `depends_on` with a
# condition is not honoured by every compose implementation, and an instance
# that is running is not the same as an instance that can sign a token.
set -euo pipefail

cd "$(dirname "$0")"

COMPOSE_FILE=compose.yml

if command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose -f "$COMPOSE_FILE")
elif docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose -f "$COMPOSE_FILE")
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose -f "$COMPOSE_FILE")
else
  echo "Install podman-compose or docker compose first." >&2
  exit 1
fi

# name | address to poll | optional pattern the answer must contain.
# The order is the order things come up in.
#
# The applications are polled at /start rather than at /, because serving a page
# is not the same as being able to reach the instance behind it: /start does
# discovery over the back channel first. A stack that answers here is one where
# a sign-in will work, which is not true of one that merely responds.
INSTANCES=(
  # Not /_localstack/health, which answers as soon as the services are up -
  # before the key, the table and the bucket exist. Reading a seeded object back
  # proves the provisioning ran *and* that the container answering on this port
  # is the provisioned one, which /_localstack/init alone does not: a container
  # being replaced can still answer for its predecessor's state, and an instance
  # that asks for a relying party one second too early is refused.
  'localstack|http://localhost:4566/sag-clients/clients/rp-lambda.json|"client_name"'
  'sag-node|http://localhost:8791/healthz'
  'sag-workers|http://localhost:8792/healthz'
  'sag-lambda|http://localhost:8793/healthz'
  'rp-node|http://localhost:8801/start'
  'rp-workers|http://localhost:8802/start'
  'rp-lambda|http://localhost:8803/start'
  'rp-cimd|http://localhost:8804/start'
)

# The services that cannot work until AWS has been provisioned, restarted once
# it has been. Only the Lambda instance reads KMS, DynamoDB and S3.
NEEDS_AWS=(sag-lambda)

wait_for() {
  local name="$1" url="$2" pattern="${3:-}" deadline=$(($(date +%s) + 240))
  printf '  %-20s' "$name"
  while :; do
    if body="$(curl -sf --max-time 4 "$url" 2>/dev/null)"; then
      if [ -z "$pattern" ] || printf '%s' "$body" | grep -qF "$pattern"; then
        echo 'ready'
        return 0
      fi
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo 'NOT READY'
      echo
      echo "  $name never answered on $url. Its log usually says why:"
      echo "    ./stack.sh logs $name"
      return 1
    fi
    sleep 2
  done
}

map() {
  cat <<'MAP'

  SAG local stack
  ------------------------------------------------------------------------
  Sign in                        signing           state            clients
  http://localhost:8801          a local key file  in-process map   JSON files
  http://localhost:8802          a private Worker  Durable Object   environment
  http://localhost:8803          AWS KMS           DynamoDB         an S3 bucket
  http://localhost:8804          the Node instance again, reached by a client
                                 that describes itself and is registered nowhere

  The instances themselves, if you would rather drive them directly:
    http://localhost:8791  Node        .well-known/openid-configuration
    http://localhost:8792  workerd     jwks.json
    http://localhost:8793  Lambda      healthz
    http://localhost:4566  LocalStack  _localstack/health

  Everything shares the host's network, so these are the same addresses from
  a terminal, from a browser, and from inside any of the containers.

  Sign-in codes are printed to each instance's log, and shown on the page:
    ./stack.sh logs sag-node

  Check the whole thing without a browser:
    ./stack.sh verify

MAP
}

case "${1:-up}" in
  up)
    shift || true
    "${COMPOSE[@]}" build "$@"
    echo
    echo '  Waiting for the stack. The first start builds workerd and provisions AWS,'
    echo '  so give it a couple of minutes.'
    echo
    # Everything in one pass. Starting AWS first and the rest afterwards would be
    # the obvious order, but a second `up` re-touches the services the first one
    # started - depends_on pulls them back in - and a container recreated
    # underneath a running instance is a connection failure in whatever was
    # talking to it.
    "${COMPOSE[@]}" up -d --force-recreate
    echo

    # So the order is enforced afterwards instead. compose.yml asks for it with
    # depends_on, but not every compose implementation honours a condition, and
    # the instance that signs with KMS needs the key, the table and the bucket to
    # exist before its first request rather than eventually: a relying party read
    # before the bucket was seeded is a client that does not exist yet.
    IFS='|' read -r name url pattern <<<"${INSTANCES[0]}"
    wait_for "$name" "$url" "$pattern" || exit 1
    "${COMPOSE[@]}" restart "${NEEDS_AWS[@]}" >/dev/null
    echo
    failed=0
    for entry in "${INSTANCES[@]:1}"; do
      IFS='|' read -r name url pattern <<<"$entry"
      wait_for "$name" "$url" "$pattern" || failed=1
    done
    [ "$failed" -eq 0 ] || exit 1
    map
    ;;
  down)
    shift || true
    # The volumes hold generated key material and spent authorisation codes.
    # Keeping them across a `down` would make the stack a thing with a history,
    # which is not what a test rig is for.
    "${COMPOSE[@]}" down --volumes "$@"
    ;;
  wait)
    for entry in "${INSTANCES[@]}"; do
      IFS='|' read -r name url pattern <<<"$entry"
      wait_for "$name" "$url" "$pattern"
    done
    ;;
  map)
    map
    ;;
  verify)
    shift || true
    node verify.js "$@"
    ;;
  *)
    "${COMPOSE[@]}" "$@"
    ;;
esac
