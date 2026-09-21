# 0007. Accessibility review with a real screen reader

Status: Proposed

## Context

Automated markup checks and Chromium viewport tests do not establish whether
someone can complete authentication with assistive technology. Error states,
code expiry, focus changes, and resend controls matter as much as page labels.

## Proposal

Review every SAG page and complete sign-in and sign-out with NVDA/Firefox and
VoiceOver/Safari, recording the tested versions. Include keyboard-only use,
zoom and reflow, visible focus, reading order, input labels, error association,
status announcements, and page language. Use [WCAG 2.2
AA](https://www.w3.org/TR/WCAG22/) as the target for SAG-owned pages; do not
claim that automated checks certify conformance or cover upstream interfaces.

Exercise invalid and expired codes, resend availability, rate-limit messages,
continue screens, upstream refusal, and logout confirmation. Announce relevant
state changes without reading a countdown every second. Preserve sensible
focus after a failed submission, and provide a clear restart after expiry.

Permit code paste, autofill, and password-manager assistance. Do not require
memorisation or manual transcription where assistive mechanisms can supply
input. Verify that security time limits have an accessible explanation and
recovery path; document any essential timing exception with its justification.

Keep the test script and redacted outcomes in the UI test guide. Fix blocking
issues, retest the complete affected flow, and add meaningful automated
regressions where possible. Record remaining issues explicitly. Repeat the
manual cases when page structure or authentication interaction changes.

## Cost

Two browser/screen-reader environments and manual flow testing, with fix cost
determined by findings. Passing markup checks does not imply the necessary
changes will be small. Acceptance requires completed flows, including error
and timeout recovery, and recorded evidence against the stated target.
