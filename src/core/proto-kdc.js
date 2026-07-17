// Key distribution with a trusted server, as message-sequence data: the Needham–Schroeder symmetric-key protocol,
// the replay of an old session key that breaks it, the repair with Bob's own nonce in the ticket, and a
// Kerberos-style ticket flow (an authentication server, a ticket-granting server, and a service).
//   S.Proto.needhamSchroeder({seed}) -> result      the five messages, each party's knowledge after each
//   S.Proto.nsReplay({seed}) -> result              an old run, the old key leaking, Eve replaying message 3
//   S.Proto.nsFixed({seed, replay}) -> result        the repaired protocol; with replay: true, Eve's replay fails
//   S.Proto.kerberos({seed, user, service}) -> result
// A result is run.result() from proto-base.js plus {summary}.
(function (S) {
  'use strict';
  const Pr = (S.Proto = S.Proto || {});
  const { atom: a, enc } = Pr;
  const key = (n) => a(n, 'key'), nonce = (n) => a(n, 'nonce'), id = (n) => a(n, 'id');

  const nsParties = (extra = []) => [
    { id: 'A', label: 'Alice', knows: [id('A'), id('B'), id('S'), key('Kas'), nonce('Na')] },
    { id: 'B', label: 'Bob', knows: [id('A'), id('B'), id('S'), key('Kbs'), nonce('Nb')] },
    { id: 'S', label: 'Server', role: 'trusted', knows: [id('A'), id('B'), id('S'), key('Kas'), key('Kbs'), key('Kab')] },
    ...extra,
  ];
  const nb1 = a('Nb−1', 'nonce', { from: 'Nb' });

  /** the five messages; the run is `r`, the names of the session key and nonces may be renamed for an old run */
  const nsMessages = (r, o = {}) => {
    const Kab = key(o.Kab || 'Kab'), Na = nonce(o.Na || 'Na'), Nb = nonce(o.Nb || 'Nb');
    const Nb1 = a(`${Nb.name}−1`, 'nonce', { from: Nb.name });
    r.send('A', 'S', [id('A'), id('B'), Na], { label: 'request', note: 'Alice asks the server for a key to talk to Bob, with a fresh nonce' });
    r.send('S', 'A', [enc(key('Kas'), Na, id('B'), Kab, enc(key('Kbs'), Kab, id('A')))], { label: 'key and ticket', note: 'Only Alice can open this; inside is a ticket only Bob can open' });
    r.check('A', r.knows('A', Na), `the nonce ${Na.name} inside matches the one she sent, so this reply is fresh`);
    r.send('A', 'B', [enc(key('Kbs'), Kab, id('A'))], { label: 'ticket', note: 'Alice forwards the ticket she cannot read' });
    r.send('B', 'A', [enc(Kab, Nb)], { label: 'challenge', note: 'Bob checks that the other side holds the key' });
    r.send('A', 'B', [enc(Kab, Nb1)], { label: 'response', note: 'Alice proves she can use the key' });
    r.check('B', r.knows('B', Kab), `the response opens under ${Kab.name} and contains ${Nb1.name}: Bob accepts ${Kab.name} as a key shared with Alice`);
  };
  Pr.needhamSchroeder = (o = {}) => {
    const r = Pr.run({ title: 'Needham–Schroeder (symmetric key)', seed: o.seed, parties: nsParties() });
    nsMessages(r);
    const res = r.result();
    res.summary = 'Alice and Bob share Kab, which only they and the server know. Nothing in Bob\'s messages tells him the ticket is new.';
    return res;
  };

  Pr.nsReplay = (o = {}) => {
    const r = Pr.run({
      title: 'Replay of an old session key', seed: o.seed,
      parties: nsParties([{ id: 'E', label: 'Eve', role: 'eavesdropper', knows: [id('A'), id('B'), id('E')] }]),
    });
    r.note('Months ago Alice and Bob ran the protocol with session key K′ab. Eve recorded every message.');
    r.learn('S', key('K′ab')); r.learn('A', nonce('N′a')); r.learn('B', nonce('N′b'));
    nsMessages(r, { Kab: 'K′ab', Na: 'N′a', Nb: 'N′b' });
    r.note('Later the old key K′ab leaks (an old laptop, a careless log). Old keys are not meant to matter any more.');
    r.learn('E', key('K′ab'));
    r.learn('B', nonce('Nb2'));
    const ticket = enc(key('Kbs'), key('K′ab'), id('A'));
    r.send('E', 'B', [ticket], { as: 'A', label: 'replayed ticket', note: 'Eve replays the old message 3' });
    r.send('B', 'E', [enc(key('K′ab'), nonce('Nb2'))], { label: 'challenge', note: 'Bob thinks he is talking to Alice' });
    r.send('E', 'B', [enc(key('K′ab'), a('Nb2−1', 'nonce', { from: 'Nb2' }))], { as: 'A', label: 'response', note: 'Eve holds K′ab, so she can answer' });
    r.check('B', true, 'the response is correct, so Bob accepts K′ab as a fresh key with Alice');
    const res = r.result();
    res.ok = false;
    res.attack = { success: r.knows('E', key('K′ab')), victim: 'B', key: 'K′ab' };
    res.summary = 'Bob accepted a key Eve knows, because nothing in the ticket was fresh to him: Eve now talks to Bob as Alice.';
    return res;
  };

  Pr.nsFixed = (o = {}) => {
    const parties = nsParties(o.replay ? [{ id: 'E', label: 'Eve', role: 'eavesdropper', knows: [id('A'), id('B'), id('E'), key('K′ab'), Pr.enc(key('Kbs'), key('K′ab'), id('A'), nonce('J′b'))] }] : []);
    parties[1].knows.push(nonce('Jb'));
    const r = Pr.run({ title: o.replay ? 'Replay against the repaired protocol' : 'Needham–Schroeder, repaired', seed: o.seed, parties });
    if (o.replay) {
      r.note('Eve holds an old ticket {K′ab, A, J′b}Kbs and the leaked K′ab, as before.');
      r.send('E', 'B', [id('A')], { as: 'A', label: 'hello', note: 'Eve starts a session as Alice' });
      r.send('B', 'E', [enc(key('Kbs'), id('A'), nonce('Jb'))], { label: 'Bob\'s nonce', note: 'Bob seals a fresh nonce Jb for the server' });
      r.send('E', 'B', [enc(key('Kbs'), key('K′ab'), id('A'), nonce('J′b'))], { as: 'A', label: 'replayed ticket', note: 'Eve can only replay the old ticket' });
      r.check('B', false, 'the ticket carries J′b, not the Jb he just issued: it is stale, and Bob rejects it');
      const res = r.result();
      res.attack = { success: false };
      res.summary = 'The replay fails: a ticket is now bound to a nonce Bob chose for this session, which no old ticket can contain.';
      return res;
    }
    r.send('A', 'B', [id('A')], { label: 'hello', note: 'Alice tells Bob she wants to talk' });
    r.send('B', 'A', [enc(key('Kbs'), id('A'), nonce('Jb'))], { label: 'Bob\'s nonce', note: 'Bob seals a fresh nonce for the server' });
    r.send('A', 'S', [id('A'), id('B'), nonce('Na'), enc(key('Kbs'), id('A'), nonce('Jb'))], { label: 'request' });
    r.send('S', 'A', [enc(key('Kas'), nonce('Na'), id('B'), key('Kab'), enc(key('Kbs'), key('Kab'), id('A'), nonce('Jb')))], { label: 'key and ticket', note: 'The ticket now carries Bob\'s nonce' });
    r.send('A', 'B', [enc(key('Kbs'), key('Kab'), id('A'), nonce('Jb'))], { label: 'ticket' });
    r.check('B', true, 'the ticket contains Jb, the nonce he issued for this session, so it is fresh');
    r.send('B', 'A', [enc(key('Kab'), nonce('Nb'))], { label: 'challenge' });
    r.send('A', 'B', [enc(key('Kab'), nb1)], { label: 'response' });
    r.check('B', r.knows('B', key('Kab')), 'Nb−1 comes back under Kab: Bob accepts');
    const res = r.result();
    res.summary = 'Bob\'s nonce travels through the server into the ticket, so Bob knows the ticket was made for this session.';
    return res;
  };

  // ---- a Kerberos-style flow: log in once, get a ticket-granting ticket, use it to get service tickets
  Pr.kerberos = (o = {}) => {
    const user = o.user || 'C', svc = o.service || 'V';
    const Kc = key('Kc'), Ktgs = key('Ktgs'), Kv = key('Kv'), Kctgs = key('Kc,tgs'), Kcv = key('Kc,v');
    const r = Pr.run({
      title: 'Kerberos-style tickets', seed: o.seed,
      parties: [
        { id: user, label: 'Client', knows: [id(user), id('AS'), id('TGS'), id(svc), a('password', 'secret'), a('Kc', 'key', { from: 'password' }), nonce('N1'), nonce('N2'), a('T1', 'time'), a('T2', 'time')] },
        { id: 'AS', label: 'Authentication server', role: 'trusted', knows: [id('AS'), Kc, Ktgs, Kctgs, a('expiry', 'time')] },
        { id: 'TGS', label: 'Ticket-granting server', role: 'trusted', knows: [id('TGS'), Ktgs, Kv, Kcv, a('expiry', 'time')] },
        { id: svc, label: 'Service', knows: [id(svc), Kv] },
      ],
    });
    r.note('The client\'s long-term key Kc is derived from the password (a slow key derivation such as PBKDF2); the password itself never crosses the network.');
    r.learn(user, Kc);
    const tgt = enc(Ktgs, Kctgs, id(user), a('expiry', 'time'));
    r.send(user, 'AS', [id(user), id('TGS'), nonce('N1')], { label: 'AS request', note: 'In the clear: who I am, and that I want a ticket-granting ticket' });
    r.send('AS', user, [enc(Kc, Kctgs, nonce('N1')), tgt], { label: 'AS reply', note: 'A session key for the TGS, sealed under Kc, and the TGT sealed under the TGS\'s key' });
    r.check(user, r.knows(user, Kctgs), 'the reply opens under Kc and returns N1, so the client now holds Kc,tgs (and can forget the password)');
    r.send(user, 'TGS', [tgt, enc(Kctgs, id(user), a('T1', 'time')), id(svc), nonce('N2')], { label: 'TGS request', note: 'The TGT plus an authenticator: a fresh timestamp under the session key' });
    r.check('TGS', r.knows('TGS', Kctgs), 'the TGT opens under Ktgs and gives Kc,tgs; the authenticator opens under it and T1 is within the allowed clock skew');
    const ticket = enc(Kv, Kcv, id(user), a('expiry', 'time'));
    r.send('TGS', user, [enc(Kctgs, Kcv, nonce('N2')), ticket], { label: 'TGS reply', note: 'A key for the service, and a service ticket the client cannot read' });
    r.send(user, svc, [ticket, enc(Kcv, id(user), a('T2', 'time'))], { label: 'service request' });
    r.check(svc, r.knows(svc, Kcv), 'the ticket opens under Kv, the authenticator under Kc,v, and T2 is fresh and not seen before');
    r.send(svc, user, [enc(Kcv, a('T2', 'time'))], { label: 'mutual authentication', note: 'Returning T2 under Kc,v proves the service could open the ticket' });
    r.check(user, true, 'the service is genuine: it knew Kv');
    const res = r.result();
    res.summary = 'One password entry yields a TGT; each service ticket comes from the TGS without the password again. Timestamps, not nonces, stop replays, so clocks must agree.';
    return res;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
