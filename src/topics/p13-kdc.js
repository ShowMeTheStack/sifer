// Part 13, key distribution with a trusted server, as message-sequence charts: Needham–Schroeder, Eve's replay of
// an old ticket once its key has leaked, the repair with Bob's own nonce in the ticket, and Kerberos-style tickets.
// Under each lifeline, what that party knows after each step, worked out by the protocol engine (a party opens an
// encryption only when it holds the key).
(function (S) {
  'use strict';
  const U = S.P12, Q = S.P13, Pr = () => S.Proto;

  const NS = {
    ns: { run: (seed) => Pr().needhamSchroeder({ seed }), order: ['S', 'A', 'B'], check: ['Na matches: fresh', 'Nb−1 under Kab: accept'], note: [], sub: 'Alice gets a key for Bob from a server both trust' },
    replay: { run: (seed) => Pr().nsReplay({ seed }), order: ['S', 'A', 'B', 'E'], check: ['N′a matches', 'accepts K′ab', 'accepts K′ab: Eve knows it'], note: ['months ago: an old run, recorded by Eve', 'later: the old key K′ab leaks to Eve'], sub: 'an old run, a leaked key, and an old ticket sent again' },
    fixed: { run: (seed) => Pr().nsFixed({ seed }), order: ['S', 'A', 'B'], check: ['Jb in the ticket: fresh', 'Nb−1 under Kab: accept'], note: [], sub: 'Bob\'s own nonce Jb goes into the ticket' },
    'fixed-replay': { run: (seed) => Pr().nsFixed({ seed, replay: true }), order: ['S', 'A', 'B', 'E'], check: ['J′b, not Jb: stale, reject'], note: ['Eve holds an old ticket and the leaked K′ab'], sub: 'Eve tries the same replay against the repair' },
  };
  function ns(inp) {
    const sc = NS[inp.scenario], res = sc.run(+inp.seed);
    const frames = Q.mscFrames(res, { order: sc.order, check: sc.check, note: sc.note, sub: sc.sub, bad: (id, a) => id === 'E' && /^K/.test(a), hl: (s) => (s.type === 'message' ? [Math.min(5, s.i)] : s.type === 'check' ? [6] : [0]) });
    const last = frames[frames.length - 1];
    last.say = last.say.replace(/([^.!?])$/, '$1.') + ' ' + res.summary;
    last.facts.summary = res.summary;
    return { frames, def: U.def('Needham–Schroeder (symmetric key)', ['A and B each share a long-term key with S: Kas, Kbs', '1. A → S: A, B, Na', '2. S → A: {Na, B, Kab, {Kab, A}Kbs}Kas', '3. A → B: {Kab, A}Kbs', '4. B → A: {Nb}Kab', '5. A → B: {Nb − 1}Kab', 'flaw: nothing in message 3 is fresh to B']) };
  }
  S.topic({
    id: 'p13-ns', family: 'p13-kdc', order: 10, title: 'Needham–Schroeder, its replay, and the repair',
    blurb: 'A trusted server hands Alice a fresh key for Bob, and a ticket only Bob can read. Nothing in the ticket is fresh to Bob, so once an old key leaks, Eve can replay its ticket; Bob\'s own nonce in the ticket stops her.',
    inputs: [
      { id: 'scenario', kind: 'choice', label: 'Run', def: 'ns', options: [{ value: 'ns', label: 'the protocol' }, { value: 'replay', label: 'Eve replays an old ticket' }, { value: 'fixed', label: 'the repaired protocol' }, { value: 'fixed-replay', label: 'the replay against the repair' }] },
      { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 999 },
    ],
    presets: [
      { label: 'The protocol', values: { scenario: 'ns' } },
      { label: 'The replay attack', values: { scenario: 'replay' } },
      { label: 'The repair', values: { scenario: 'fixed' } },
      { label: 'The replay fails', values: { scenario: 'fixed-replay' } },
    ],
    run: ns,
    predict: [
      { at: (f) => f.meta && f.meta.step && f.meta.step.type === 'message' && /^ticket$/.test(f.meta.step.label), pick: 'option', options: ['yes', 'no'], ask: 'Alice is forwarding the ticket. Could she read what is inside it?', answer: 'no', explain: 'It is sealed under Kbs, which only Bob and the server hold.' },
      { at: (f) => f.meta && f.meta.step && f.meta.step.label === 'replayed ticket' && f.meta.step.type === 'message', pick: 'option', options: ['accept it', 'reject it'], ask: 'Eve has sent an old ticket as if from Alice. Will Bob end up accepting the key?', answer: (fr) => (fr.some((f) => f.meta.step.type === 'check' && f.meta.step.party === 'B' && !f.meta.step.ok) ? 'reject it' : 'accept it'), explain: (fr) => fr[fr.length - 1].say },
    ],
    quiz: [
      { q: 'Why does Alice include a nonce Na in message 1?', options: ['to identify herself', 'so she knows the server\'s reply is fresh, not a replay', 'to encrypt the request', 'for Bob'], answer: 1, why: 'The reply must contain her new Na.' },
      { q: 'What lets Eve\'s replay work?', options: ['she knows Kbs', 'an old session key leaked, and Bob cannot tell an old ticket from a new one', 'she breaks AES', 'Alice helps her'], answer: 1, why: 'The ticket {Kab, A}Kbs carries nothing Bob chose for this session.' },
      { q: 'How does the repair stop the replay?', options: ['longer keys', 'Bob\'s fresh nonce goes through the server into the ticket', 'timestamps on Alice\'s side', 'removing the server'], answer: 1, why: 'Only a ticket made for this session can contain Jb.' },
      { q: 'What does the server know in this protocol?', options: ['nothing', 'every session key it hands out', 'only Kas', 'only the nonces'], answer: 1, why: 'A key distribution centre is trusted with every key; that is its weakness.' },
    ],
  });

  function kerberos(inp) {
    const res = Pr().kerberos({ seed: +inp.seed });
    const frames = Q.mscFrames(res, { order: ['AS', 'C', 'TGS', 'V'], labels: { AS: 'Auth. server', TGS: 'Ticket server' }, check: ['opens with Kc: has Kc,tgs', 'TGT valid, T1 fresh', 'ticket valid, T2 fresh', 'the service is genuine'], note: ['Kc comes from the password, which is never sent'], sub: 'log in once, then get a ticket for each service', hl: (s) => (s.type === 'message' ? [Math.min(6, s.i)] : [7]) });
    const last = frames[frames.length - 1];
    last.say = last.say.replace(/([^.!?])$/, '$1.') + ' ' + res.summary;
    last.facts.summary = res.summary;
    return { frames, def: U.def('Kerberos, in outline', ['C ↔ AS: password-derived Kc gets Kc,tgs and a TGT', 'TGT = {Kc,tgs, C, expiry}Ktgs', 'C ↔ TGS: TGT + {C, T1}Kc,tgs gets Kc,v and a ticket', 'ticket = {Kc,v, C, expiry}Kv', 'C ↔ V: ticket + {C, T2}Kc,v', 'V → C: {T2}Kc,v proves the service', 'timestamps, not nonces: clocks must agree', 'one password entry, many services']) };
  }
  S.topic({
    id: 'p13-kerberos', family: 'p13-kdc', order: 20, title: 'A Kerberos ticket flow',
    blurb: 'Log in once: the authentication server gives a ticket-granting ticket, the ticket server swaps it for a ticket to a service, and the service proves itself back. Watch who can open what.',
    inputs: [{ id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 999 }],
    presets: [{ label: 'A login and one service', values: { seed: 1 } }, { label: 'Another run', values: { seed: 7 } }],
    run: kerberos,
    predict: [
      { at: (f) => f.meta && f.meta.step && f.meta.step.label === 'TGS reply', pick: 'option', options: ['the client', 'the service', 'both', 'neither'], ask: 'Who can open the service ticket just issued?', answer: 'the service', explain: 'It is sealed under Kv, the service\'s own key; the client only carries it.' },
    ],
    quiz: [
      { q: 'What does the ticket-granting ticket spare the user?', options: ['the password for each service', 'the clock', 'the server', 'encryption'], answer: 0, why: 'After logging in once, service tickets come from the TGS without the password again.' },
      { q: 'Who can read the TGT?', options: ['the client', 'the ticket-granting server', 'the service', 'anyone'], answer: 1, why: 'It is sealed under Ktgs.' },
      { q: 'What stops an authenticator from being replayed?', options: ['a nonce from the service', 'its timestamp, checked against the clock and a cache of recent ones', 'nothing', 'the password'], answer: 1, why: 'Kerberos relies on loosely synchronised clocks.' },
      { q: 'How does the service prove itself to the client?', options: ['by its IP address', 'by returning T2 under Kc,v, which needs Kv to obtain', 'with a certificate', 'it does not'], answer: 1, why: 'Only a holder of Kv could open the ticket and learn Kc,v.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
