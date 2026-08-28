# 0013. Production session cookies use the `__Host-` prefix

Date: 2026-08-27
Status: Accepted

## Context

A secure, HTTP-only cookie can still be shadowed by a `Domain` cookie planted
by another application on a parent domain. The browser-enforced `__Host-`
prefix prevents that, but requires `Secure`, `Path=/`, and no `Domain`.

## Decision

Prefix the configured session cookie name with `__Host-` whenever `SAG_DEV` is
false. Production session cookies always use `Path=/`. Development keeps the
unprefixed name, insecure transport support, and issuer base-path scope.

## Consequences

Deploying this change invalidates existing production session cookies rather
than retaining an unprefixed compatibility path that would preserve the cookie
planting risk. People sign in again once. An issuer mounted below a host path
now sends its cookie to every path on that host, although the cookie remains
host-only, HTTP-only, and unreadable by applications there.
