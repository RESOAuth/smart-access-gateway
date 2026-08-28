// The default stylesheet.
//
// Every page is built to be usable with none of this applied, so the CSS only
// ever improves comfort: it never carries meaning, never hides content, and
// never positions anything the document order does not already imply.
//
// Sizes are in rem throughout so that a browser or OS text-size preference
// scales the whole interface, and the layout is a single column that reflows
// rather than a grid that breaks. That is what makes it survive a 400% zoom,
// which is the WCAG 1.4.10 reflow requirement.
//
// Colour comes from custom properties defined three times: the light palette on
// a bare `:root`, the dark palette under `prefers-color-scheme`, and the dark
// palette again under `[data-theme="dark"]`. The third block is what lets the
// toggle in sag.js win over the operating system in either direction, and it
// comes last so it does.

export const DEFAULT_CSS = `
:root {
  color-scheme: light;

  --bg: #f2f4f8;
  --bg-accent: #e7ecf6;
  --panel: #ffffff;
  --panel-sunk: #f7f8fb;
  --ink: #14161b;
  --ink-soft: #525a68;
  --ink-faint: #6b7382;
  --line: #dde1e9;
  --line-strong: #b9c1cf;
  --accent: #1d4ed8;
  --accent-hover: #1a44bd;
  --accent-ink: #ffffff;
  --error: #9c0f27;
  --error-bg: #fdf2f4;
  --error-line: #edbfc8;
  --ok: #0f5c3f;
  --focus: #a86400;
  --radius: 0.875rem;
  --radius-sm: 0.5rem;
  --shadow: 0 0.0625rem 0.125rem rgba(16, 24, 40, 0.05), 0 1.25rem 2.5rem -1.5rem rgba(16, 24, 40, 0.22);
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;

    --bg: #0d0f13;
    --bg-accent: #171b22;
    --panel: #171a20;
    --panel-sunk: #12151a;
    --ink: #f0f2f6;
    --ink-soft: #a8b0be;
    --ink-faint: #8d95a3;
    --line: #2c313b;
    --line-strong: #454c59;
    --accent: #86a6ff;
    --accent-hover: #a2bcff;
    --accent-ink: #0b0e14;
    --error: #ffa3b0;
    --error-bg: #2a1318;
    --error-line: #5c2a33;
    --ok: #7bd9af;
    --focus: #ffc65c;
    --shadow: 0 0.0625rem 0.125rem rgba(0, 0, 0, 0.5), 0 1.25rem 2.5rem -1.5rem rgba(0, 0, 0, 0.7);
  }
}

/* Last, so an explicit choice beats the operating system's. */
:root[data-theme="dark"] {
  color-scheme: dark;

  --bg: #0d0f13;
  --bg-accent: #171b22;
  --panel: #171a20;
  --panel-sunk: #12151a;
  --ink: #f0f2f6;
  --ink-soft: #a8b0be;
  --ink-faint: #8d95a3;
  --line: #2c313b;
  --line-strong: #454c59;
  --accent: #86a6ff;
  --accent-hover: #a2bcff;
  --accent-ink: #0b0e14;
  --error: #ffa3b0;
  --error-bg: #2a1318;
  --error-line: #5c2a33;
  --ok: #7bd9af;
  --focus: #ffc65c;
  --shadow: 0 0.0625rem 0.125rem rgba(0, 0, 0, 0.5), 0 1.25rem 2.5rem -1.5rem rgba(0, 0, 0, 0.7);
}

*, *::before, *::after { box-sizing: border-box; }

body {
  margin: 0;
  padding: 2rem 1rem;
  min-height: 100vh;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1.25rem;
  background: var(--bg);
  /* A whisper of colour behind the card, so the page reads as a considered
     surface rather than a blank browser default. It is a gradient on the
     background only: nothing sits on top of it that needs contrast. */
  background-image: radial-gradient(70rem 40rem at 50% -10%, var(--bg-accent), var(--bg) 70%);
  background-repeat: no-repeat;
  color: var(--ink);
  font: 1rem/1.55 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  -webkit-text-size-adjust: 100%;
  text-rendering: optimizeLegibility;
}

/* The card must not stop the page scrolling when zoomed, so it has no fixed
   height and the flex centring collapses to top-aligned once content is tall. */
main {
  width: 100%;
  max-width: 26rem;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 2rem;
  box-shadow: var(--shadow);
}
@media (max-width: 26rem) {
  body { padding: 0; gap: 0; background-image: none; }
  main { border-radius: 0; border-left: 0; border-right: 0; box-shadow: none; padding: 1.5rem 1.25rem 2rem; }
  footer { padding: 1rem 1.25rem 2rem; }
}

h1 {
  margin: 0 0 0.5rem;
  font-size: 1.5rem;
  line-height: 1.2;
  letter-spacing: -0.021em;
  font-weight: 650;
  text-wrap: balance;
}

.lede { margin: 0 0 1.5rem; color: var(--ink-soft); text-wrap: pretty; }
.lede:last-child { margin-bottom: 0; }
.lede strong { color: var(--ink); font-weight: 600; }

.client-logo { margin: 0 0 1rem; }
.client-logo img { display: block; max-width: 7.5rem; max-height: 2.5rem; width: auto; height: auto; margin: 0 auto; }

form { margin: 0; }

.field { margin-bottom: 1.5rem; }
label { display: block; margin-bottom: 0.375rem; font-weight: 600; }
.hint {
  display: block;
  margin-bottom: 0.5rem;
  color: var(--ink-soft);
  font-size: 0.875rem;
  font-weight: 400;
}

input[type="email"], input[type="text"] {
  display: block;
  width: 100%;
  padding: 0.6875rem 0.8125rem;
  font: inherit;
  color: var(--ink);
  background: var(--panel);
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  transition: border-color 0.12s ease, box-shadow 0.12s ease;
}
input[type="email"]:hover, input[type="text"]:hover { border-color: var(--ink-faint); }
input[type="email"]:focus, input[type="text"]:focus { border-color: var(--accent); }
input[aria-invalid="true"] { border-color: var(--error); }

/* A one-time code is read back character by character, so give it room and
   tracking, and lining figures so the glyph widths do not jump as it is typed. */
input.code {
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 1.375rem;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.3em;
  text-indent: 0.3em;
  text-align: center;
  padding: 0.6875rem 0.5rem;
}

button, .button {
  display: block;
  width: 100%;
  padding: 0.75rem 1rem;
  font: inherit;
  font-weight: 600;
  text-align: center;
  text-decoration: none;
  color: var(--accent-ink);
  background: var(--accent);
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: background-color 0.12s ease, border-color 0.12s ease, color 0.12s ease;
}
button:hover, .button:hover { background: var(--accent-hover); }
button:active, .button:active { transform: translateY(0.0625rem); }
button.secondary, .button.secondary {
  color: var(--ink);
  background: transparent;
  border-color: var(--line-strong);
  font-weight: 500;
}
button.secondary:hover, .button.secondary:hover { background: var(--panel-sunk); border-color: var(--ink-faint); }

/* A submission in flight. Script sets the attribute; the label is swapped in
   the DOM rather than here, so nothing depends on generated content. */
button[data-busy] { cursor: progress; opacity: 0.7; }

/* Secondary actions read as one group rather than a stack of equal buttons. */
.stack > * + * { margin-top: 0.625rem; }
.also { margin-top: 1.5rem; padding-top: 1.25rem; border-top: 1px solid var(--line); }
.also > * + * { margin-top: 0.625rem; }

/* One visible focus treatment for every interactive element, at a contrast
   that holds up in both colour schemes. */
:focus-visible {
  outline: 3px solid var(--focus);
  outline-offset: 2px;
  border-radius: var(--radius-sm);
}

.error {
  margin: 0 0 1.5rem;
  padding: 0.8125rem 0.9375rem;
  color: var(--error);
  background: var(--error-bg);
  border: 1px solid var(--error-line);
  border-left: 0.1875rem solid currentColor;
  border-radius: var(--radius-sm);
}
.error strong { display: block; color: var(--error); }

.notice {
  margin: 0 0 1.5rem;
  padding: 0.8125rem 0.9375rem;
  color: var(--ink-soft);
  background: var(--panel-sunk);
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius-sm);
  font-size: 0.9375rem;
}
.notice code {
  display: block;
  margin: 0.375rem 0;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: 0.2em;
  color: var(--ink);
  overflow-wrap: anywhere;
}
.notice code:only-child { margin: 0; }

/* Who is being signed in: an avatar when there is one, then the name and the
   address. The row wraps rather than truncating, because a clipped address is
   exactly the thing somebody is checking. */
.identity {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin: 0 0 1.5rem;
  padding: 0.8125rem 0.9375rem;
  background: var(--panel-sunk);
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  word-break: break-word;
}
.identity .who { min-width: 0; }
.identity strong { display: block; }
.identity span { display: block; color: var(--ink-soft); font-size: 0.875rem; }
.identity img.avatar,
.identity .avatar {
  flex: 0 0 auto;
  width: 2.75rem;
  aspect-ratio: 1;
  border-radius: 50%;
  object-fit: cover;
  background: var(--bg-accent);
  color: var(--ink-soft);
  border: 1px solid var(--line);
  font-size: 1rem;
  font-weight: 600;
  line-height: 2.625rem;
  text-align: center;
  letter-spacing: 0.02em;
}

.choices { list-style: none; margin: 0 0 1.5rem; padding: 0; }
.choices li + li { margin-top: 0.625rem; }

footer {
  width: 100%;
  max-width: 26rem;
  padding: 0 2rem;
  color: var(--ink-faint);
  font-size: 0.8125rem;
  text-align: center;
}
footer a { color: inherit; }
footer p { margin: 0.375rem 0; }
footer .host { color: var(--ink-soft); font-weight: 500; }
footer .legal a { margin-right: 0.25rem; }
footer .logo { margin: 1.25rem 0 0; }
footer .logo img { display: block; max-width: 9rem; max-height: 2rem; width: auto; height: auto; margin: auto; }

/* The colour theme control, which only exists when sag.js has run.
   It follows the footer links, so the first Tab on the page reaches the field
   somebody came here to fill in. */
.theme {
  display: inline-flex;
  margin-top: 0.875rem;
  gap: 0.125rem;
  padding: 0.1875rem;
  background: var(--panel-sunk);
  border: 1px solid var(--line);
  border-radius: 999px;
}
.theme button {
  width: auto;
  padding: 0.3125rem;
  color: var(--ink-faint);
  background: transparent;
  border: 1px solid transparent;
  border-radius: 999px;
  line-height: 0;
  font-weight: 500;
}
.theme button:hover { color: var(--ink); background: var(--bg-accent); }
.theme button[aria-pressed="true"] {
  color: var(--ink);
  background: var(--panel);
  border-color: var(--line-strong);
}
.theme svg { width: 1.125rem; height: 1.125rem; display: block; }

/* Switching theme changes every colour token at once, and a colour transition
   across that is a visible smear rather than a nicety. sag.js sets this
   attribute for one frame around the change. */
:root[data-theme-changing] *, :root[data-theme-changing] *::before, :root[data-theme-changing] *::after {
  transition: none !important;
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
  button:active, .button:active { transform: none; }
}
@media (prefers-contrast: more), (forced-colors: active) {
  main, input, button, .button, .theme { border-width: 2px; }
  main { box-shadow: none; }
  body { background-image: none; }
}
`.trim();

/**
 * A short content fingerprint, used only to bust a cache.
 *
 * FNV-1a rather than SHA-256 because this is a cache key and not a security
 * claim, and because it has to be computed synchronously at module load on
 * every runtime SAG targets.
 */
export function assetVersion(source) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < source.length; i++) {
    hash ^= source.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(36).padStart(7, '0');
}

export const CSS_VERSION = assetVersion(DEFAULT_CSS);
