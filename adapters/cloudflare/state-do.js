// The Durable Object behind SAG's optional state on Cloudflare.
//
// A Durable Object handles one request at a time, so "have I seen this
// before?" and "how many times?" are both answered without a race. One object
// is addressed per key, which means there is no shared hot object and no
// contention at all: the object exists for as long as the record is valid and
// then its alarm empties it.
//
// Three operations: a single-use claim for authorisation codes, client
// assertions, and session revocations; a read for revocation checks; and a
// counter for OTP send limits.

export class StateGuard {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'invalid_request' }, 400);
    }
    const id = typeof body.id === 'string' ? body.id : undefined;
    if (!id) return json({ error: 'invalid_request' }, 400);

    // A minute at the low end so a clock skew cannot make a record vanish
    // early. Session revocations can live for the configured absolute session
    // lifetime, whose upper bound is one year.
    const ttl = Math.min(Math.max(Number(body.ttlSeconds) || 120, 60), 366 * 86400);
    const op = ['claim', 'has', 'increment'].includes(body.op) ? body.op : 'claim';

    if (op === 'has') {
      return json({ claimed: Boolean(await this.state.storage.get('claimed')) });
    }

    // blockConcurrencyWhile makes the read and the write one indivisible step
    // even against a future runtime that interleaves I/O within an object.
    if (op === 'increment') {
      const count = await this.state.blockConcurrencyWhile(async () => {
        const current = (await this.state.storage.get('count')) || 0;
        const next = current + 1;
        await this.state.storage.put('count', next);
        // Only the first write sets the deadline, so counting again does not
        // extend the window and turn a daily limit into a rolling one.
        if (current === 0) await this.state.storage.setAlarm(Date.now() + ttl * 1000);
        return next;
      });
      return json({ count });
    }

    const fresh = await this.state.blockConcurrencyWhile(async () => {
      const claimed = await this.state.storage.get('claimed');
      if (claimed) return false;
      await this.state.storage.put('claimed', Date.now());
      // Let the runtime discard the object rather than sweeping it ourselves.
      await this.state.storage.setAlarm(Date.now() + ttl * 1000);
      return true;
    });

    return json({ fresh });
  }

  /** Nothing outlives the record, so the alarm simply empties the object. */
  async alarm() {
    await this.state.storage.deleteAll();
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}
