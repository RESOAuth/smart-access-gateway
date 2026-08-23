// The default script.
//
// Nothing here is required for any screen to work: every control SAG renders
// server-side is a real form submission, and this file only ever adds comfort
// on top of that. It is served from our own origin as one small file rather
// than inlined, so the Content-Security-Policy needs nothing but 'self' and no
// per-response nonce has to be threaded through the script path.
//
// It is loaded synchronously in <head>, before anything is painted, because the
// first thing it does is apply a stored colour theme. Deferring that would show
// the operating system's theme for a frame and then swap - the flash that makes
// a sign-in page feel broken. Everything else waits for the document.
//
// Four enhancements, in the order they appear below:
//
//   1. a colour theme control, which exists only because this file ran, and so
//      never appears as a dead control on a page whose script was blocked;
//   2. the form_post auto-submit, which used to be an inline onload handler and
//      is here instead so that no page needs 'unsafe-inline' for script;
//   3. tidying a pasted one-time code, and submitting once it is complete;
//   4. marking a submitted form busy, so a second click cannot spend a second
//      attempt against the same code.

import { assetVersion } from './css.js';

export const DEFAULT_JS = `
(function () {
  'use strict';

  var root = document.documentElement;
  var STORE = 'sag.theme';
  var MODES = ['system', 'light', 'dark'];

  // Storage can throw outright, not merely return null: Safari in private
  // browsing and any browser told to block site data both do. A theme is a
  // convenience, so every access is allowed to fail silently.
  function stored() {
    try {
      var value = localStorage.getItem(STORE);
      return MODES.indexOf(value) > 0 ? value : 'system';
    } catch (err) {
      return 'system';
    }
  }

  function remember(mode) {
    try {
      if (mode === 'system') localStorage.removeItem(STORE);
      else localStorage.setItem(STORE, mode);
    } catch (err) {
      /* the choice still applies to this page */
    }
  }

  // 'system' means no attribute at all, so the prefers-color-scheme block in
  // the stylesheet is what decides.
  //
  // Every colour token changes at once, so transitions are suppressed for a
  // frame around the change: letting them run turns a theme switch into a
  // visible smear as each element crosses from one palette to the other.
  function apply(mode, animated) {
    if (animated === false) root.setAttribute('data-theme-changing', '');
    if (mode === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', mode);
    if (animated === false) {
      // Two frames: one for the new values to be computed, one to paint them.
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          root.removeAttribute('data-theme-changing');
        });
      });
    }
  }

  root.setAttribute('data-js', '');
  apply(stored());

  var ICONS = {
    system: 'M4 5h16v10H4zM9 19h6M12 15v4',
    light: 'M12 4V2M12 22v-2M4 12H2M22 12h-2M6 6 4.5 4.5M19.5 19.5 18 18M18 6l1.5-1.5M4.5 19.5 6 18M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
    dark: 'M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z',
  };
  var LABELS = { system: 'Match my device', light: 'Light', dark: 'Dark' };

  function icon(mode) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.75');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', ICONS[mode]);
    svg.appendChild(path);
    return svg;
  }

  function themeControl(slot) {
    var group = document.createElement('div');
    group.className = 'theme';
    group.setAttribute('role', 'group');
    group.setAttribute('aria-label', slot.getAttribute('data-label') || 'Colour theme');

    var buttons = MODES.map(function (mode) {
      var button = document.createElement('button');
      button.type = 'button';
      button.setAttribute('data-mode', mode);
      // A label rather than a tooltip: an icon-only control has to name itself
      // to anything that is not a pointer.
      button.setAttribute('aria-label', LABELS[mode]);
      button.title = LABELS[mode];
      button.appendChild(icon(mode));
      group.appendChild(button);
      return button;
    });

    function reflect(mode) {
      for (var i = 0; i < buttons.length; i++) {
        buttons[i].setAttribute('aria-pressed', buttons[i].getAttribute('data-mode') === mode ? 'true' : 'false');
      }
    }

    group.addEventListener('click', function (event) {
      var button = event.target.closest ? event.target.closest('button[data-mode]') : null;
      if (!button) return;
      var mode = button.getAttribute('data-mode');
      apply(mode, false);
      remember(mode);
      reflect(mode);
    });

    reflect(stored());
    slot.appendChild(group);
  }

  function autoSubmit(form) {
    // The relying party is expecting this POST, so it goes without asking. The
    // <noscript> button in the markup is what happens when this file does not.
    try {
      form.submit();
    } catch (err) {
      /* leave the visible button as the way through */
    }
  }

  // Codes are read off a screen and pasted with whatever spacing the mail
  // client put in, so separators are dropped and letters folded up to match
  // the alphabet the code was generated from.
  function tidyCode(input) {
    var alphanumeric = input.getAttribute('data-alphabet') !== 'numeric';
    var expected = Number(input.getAttribute('data-length')) || 0;
    var submitted = false;

    input.addEventListener('input', function () {
      var cleaned = input.value.replace(/[\\s\\-\\u2010-\\u2015_.]/g, '');
      if (alphanumeric) cleaned = cleaned.toUpperCase();
      else cleaned = cleaned.replace(/[^0-9]/g, '');
      if (cleaned !== input.value) input.value = cleaned;

      // Submitting on the last character is what a person expects of a code
      // field now. Once only: a rejected code comes back on a fresh page, and
      // re-submitting the same value would spend attempts on its own.
      if (!submitted && expected > 0 && cleaned.length === expected && input.form) {
        submitted = true;
        if (input.form.requestSubmit) input.form.requestSubmit();
        else input.form.submit();
      }
    });
  }

  // A double-clicked submit is a real problem here rather than a cosmetic one:
  // two POSTs of the same one-time code spend two of the attempts allowed for
  // it. The button is disabled after the submission has started, so its value
  // is still serialised.
  function submitOnce(form) {
    form.addEventListener('submit', function () {
      var buttons = form.querySelectorAll('button[type="submit"], button:not([type])');
      for (var i = 0; i < buttons.length; i++) {
        var button = buttons[i];
        if (button.hasAttribute('data-busy')) continue;
        var busyLabel = button.getAttribute('data-busy-label');
        button.setAttribute('data-busy', '');
        if (busyLabel) button.textContent = busyLabel;
        button.setAttribute('aria-disabled', 'true');
      }
      // After the event has been dispatched, so the browser has already taken
      // the submission and the disabled state cannot cancel it.
      setTimeout(function () {
        for (var i = 0; i < buttons.length; i++) buttons[i].disabled = true;
      }, 0);
    });
  }

  function enhance() {
    var slot = document.querySelector('[data-theme-control]');
    if (slot) {
      try {
        themeControl(slot);
      } catch (err) {
        /* an unstyled or missing control is better than a broken page */
      }
    }

    var codes = document.querySelectorAll('input[data-length]');
    for (var i = 0; i < codes.length; i++) tidyCode(codes[i]);

    var forms = document.querySelectorAll('form');
    for (var j = 0; j < forms.length; j++) {
      if (forms[j].hasAttribute('data-autosubmit')) autoSubmit(forms[j]);
      else submitOnce(forms[j]);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', enhance);
  } else {
    enhance();
  }
})();
`.trim();

export const JS_VERSION = assetVersion(DEFAULT_JS);
