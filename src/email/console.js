// The development sender: it prints the code where the developer will see it.
//
// This is the default so that `npm run dev` works with no configuration at
// all. Choosing it against a real hostname is a configuration error, caught in
// src/config.js, because it means codes are being written to a log rather than
// delivered.

export function createConsoleSender(config) {
  return {
    name: 'console',
    /**
     * @param {object} msg {to, subject, text, html, code}
     * @returns {Promise<{delivered: boolean, code?: string}>} `code` is
     *   returned only in development, where the UI shows it on the page too.
     */
    async send(msg) {
      // LOG_LEVEL=silent means silent: nothing at all on stdout. Test runs set
      // it, both to keep output readable and because a noisy child process is
      // not something a test runner should have to cope with.
      if (config.logLevel === 'silent') return { delivered: true, code: config.devMode ? msg.code : undefined };
      const banner = '─'.repeat(52);
      const lines = [
        '',
        banner,
        '  SAG email (not actually sent - EMAIL_PROVIDER=console)',
        '  To:      ' + msg.to,
        '  Subject: ' + msg.subject,
      ];
      if (msg.code) lines.push('', '  CODE:    ' + msg.code, '');
      lines.push(banner, '');
      // Written with a single call so the block cannot be interleaved with
      // other output from a concurrent request.
      console.log(lines.join('\n'));
      return { delivered: true, code: config.devMode ? msg.code : undefined };
    },
  };
}
