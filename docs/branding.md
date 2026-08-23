# Branding, whitelabelling and legal links

The sign-in pages are the only part of SAG a person ever sees, so what they
say about who is asking matters. A sign-in page on an unfamiliar domain with
no attribution is exactly what a phishing page looks like. See
[ADR 0008](adr/0008-branding-and-attribution.md) for why the defaults and the
limits on whitelabelling are what they are.

## The default

With nothing configured, the header says **RESOAuth Smart Access Gateway** and
the footer says which host is handling the sign-in and who made the software.
SAG is a RESOAuth product and the default pages say so.

## Putting your own organisation in front

```sh
UI_ORG_NAME=Borsetshire Council
UI_LOGO_URL=https://borsetshire.example/logo.svg
UI_SUPPORT_URL=https://borsetshire.example/help/signing-in
UI_TITLE=Sign in to council services
```

The organisation name, or the logo when there is one, replaces the product
name in the header: the person knows the council, not the software. The
attribution stays in the footer.

```sh
UI_WHITELABEL=true
```

Whitelabelling drops the product name from the page entirely. The footer keeps
"Powered by RESOAuth", in every configuration, because a person is entitled to
know who is processing their sign-in. A fork can rename that attribution
honestly rather than remove it:

```sh
UI_BRAND_NAME=Example Ltd
UI_BRAND_URL=https://example.test
```

## Terms and privacy

Set them for the instance, and override them for a relying party where the
application has its own:

```sh
UI_TERMS_URL=https://borsetshire.example/terms
UI_PRIVACY_URL=https://borsetshire.example/privacy

CLIENT_LEDGER_TOS_URI=https://ledger.example.com/terms
CLIENT_LEDGER_POLICY_URI=https://ledger.example.com/privacy
```

A relying party's own links win, because that is what the person is signing in
to; the instance links are the fallback and cover the sign-in service itself. A
CIMD client's published `tos_uri` and `policy_uri` are used the same way.
Nothing is shown when nothing is configured, rather than a dead link.

## Styling

```sh
CUSTOM_CSS_SNIPPET=main { border-color: rebeccapurple }
CUSTOM_CSS_REMOTE_URL=https://borsetshire.example/sag.css
```

A snippet is loaded after SAG's stylesheet. A remote URL **replaces** it, and a
snippet still applies on top, so an organisation with a design system can take
over completely without losing the ability to patch one thing. The remote URL
must be `https`.

Both arrive as stylesheets rather than as a `<style>` element in the page: your
snippet is served from `/static/custom.css`, fingerprinted so it is cached until
you change it. That is why the pages can carry a Content-Security-Policy with no
`unsafe-inline` and no per-response nonce - there is no inline style on any page
to permit. It also means a snippet has no element to break out of: a `text/css`
response with `nosniff` is never parsed as markup.

One consequence worth knowing: `CUSTOM_CSS_REMOTE_URL` adds that origin to the
policy's `style-src`, and nothing else. A remote stylesheet that itself
`@import`s from a third origin will not load.

The variables SAG's own stylesheet uses are worth knowing before you override
anything:

```css
:root {
  --bg; --bg-accent; --panel; --panel-sunk;
  --ink; --ink-soft; --ink-faint; --line; --line-strong;
  --accent; --accent-hover; --accent-ink;
  --error; --error-bg; --error-line; --ok;
  --radius; --radius-sm; --focus; --shadow;
}
```

Redefining those in a snippet re-themes every screen without touching layout.

## Light, dark and the toggle

The palette is defined three times: light on a bare `:root`, dark under
`prefers-color-scheme`, and dark again under `[data-theme="dark"]`. The third
block is what lets somebody's own choice beat their operating system, in either
direction, and it comes last so it does. A snippet that only redefines the
variables on `:root` will re-theme the light palette and leave the dark one
alone, which is usually not what you want:

```css
:root { --accent: #7a2e6d }
:root[data-theme="dark"], :root:not([data-theme="light"]) { --accent: #d9a2cf }
```

The control that switches between them is built by `/static/sag.js` and inserted
into the footer. It does not exist in the HTML at all, so a page whose script was
blocked shows no control rather than a dead one - and it is last in the document,
so the first Tab on the page reaches the field somebody came to fill in.

The choice is remembered in `localStorage` under `sag.theme`, per browser. It
never reaches SAG, so there is nothing to configure and nothing stored about
anybody. Every read and write is wrapped, because storage does not merely return
nothing in a private window - it can throw.

## What else the script does

Nothing that any screen depends on. In order: applies the stored theme before
the first paint, builds the theme control, tidies a pasted one-time code and
submits it once it is complete, marks a submitted form busy so a double click
cannot spend two attempts against the same code, and performs the `form_post`
auto-submit that used to be an inline `onload` handler.

Switch it off by pointing `CUSTOM_CSS_REMOTE_URL` at your own stylesheet if you
want a different look, but there is no flag to remove the script: the flow is
built to work without it, and removing it would only cost the person the
comforts above.

## The rules the pages keep, whatever you do to them

These are pinned by tests, so a restyle cannot quietly break them:

- **Works with no CSS and no JavaScript.** The pages are semantic HTML that
  happen to be styled. Every screen submits with scripting off, and anything
  that would need script to work - the theme control - is not in the markup at
  all rather than sitting there inert.
- **Nothing loads cross-origin.** A sign-in page that fetches a font or a
  script from a third party leaks every sign-in attempt to that third party.
  A remote stylesheet is the one exception, and it is your choice.
- **No inline style and no inline script**, which is what lets the policy on
  every page start at `default-src 'none'`.
- **Reflows at 400% zoom**, respects reduced motion and increased contrast,
  and every input has a real label.
- **Nothing steals focus on load**, which is disorienting for screen reader
  and switch access users.
- **Operator supplied text is escaped**, wherever it lands.
