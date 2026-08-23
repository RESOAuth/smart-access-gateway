#!/bin/sh
# Run SAG as whoever owns the data directory.
#
# The data directory is a bind mount from the host, and who owns it depends on
# how the container was started:
#
#   Docker, rootful    ./data belongs to the host user, uid 1000 or similar,
#                      and the container sees that uid. Drop to it, so the
#                      files SAG writes stay editable on the host.
#
#   Podman, rootless   the host user is mapped to root inside the container,
#                      so ./data appears to belong to root. Staying root is
#                      therefore staying the host user, and anything else
#                      cannot write to it at all.
#
# Reading the owner and becoming it covers both without asking anybody to
# configure a uid. Nothing here gains a privilege: under rootless Podman
# "root" is an unprivileged host user, and under Docker this drops privileges
# rather than keeping them.
set -e

dir="${SAG_DATA_DIR:-/data}"
mkdir -p "$dir" 2>/dev/null || true

if [ "$(id -u)" = "0" ]; then
  owner="$(stat -c %u "$dir" 2>/dev/null || echo 0)"
  group="$(stat -c %g "$dir" 2>/dev/null || echo 0)"
  if [ "$owner" != "0" ]; then
    # A directory belonging to somebody else: become them, and make sure the
    # application directory is readable to them too.
    exec su-exec "$owner:$group" "$@"
  fi
fi

exec "$@"
