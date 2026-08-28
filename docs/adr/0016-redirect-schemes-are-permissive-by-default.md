# 0016. Redirect schemes are permissive by default, with an optional allow-list

Date: 2026-08-27
Status: Accepted

## Context

Browser clients normally use HTTPS, while native applications legitimately use
loopback HTTP, claimed HTTPS, and private-use URI schemes. Inferring an
application type or enforcing browser rules for every client would reject
valid native integrations.

## Decision

Keep redirect URI schemes unrestricted by default. Add
`CLIENTS_REDIRECT_URI_SCHEMES` as an instance-wide allow-list, with `*` meaning
any scheme. Apply it to authorisation and post-logout redirects. Exact
registered URI matching, including the native loopback-port exception, remains
mandatory and unchanged.

## Consequences

An operator can limit a browser-only deployment to `https`, or admit an
explicit set such as `https,example-app`, without making every client declare a
type. With the default `*`, the operator or a trusted metadata publisher is
responsible for the schemes it registers.
