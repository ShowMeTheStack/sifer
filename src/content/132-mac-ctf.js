// Part 13, MACs, key establishment and protocols: the guided tour and the course, and the pages the diagram checker
// looks at. This part has no CTF challenge: its exercises compute and implement the constructions (HMAC, CMAC
// subkeys, Poly1305, HKDF), validate certificate chains, and spot protocol flaws.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.tours.has('mc-tour')) return;

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'mc-tour', title: 'Tour: MACs and protocols', blurb: 'HMAC, CMAC, Poly1305, HKDF, a man in the middle, certificate chains and TLS 1.3, in eight steps.',
    steps: [
      { route: 'part=protocols', target: '#main', text: 'Part 13 of the catalogue: MACs, key establishment and protocols. Each card runs one construction or protocol on actual bytes.' },
      { route: 'topic=p13-hmac', target: '#stageWrap', text: 'HMAC: the key XORed with ipad and opad, and two nested hashes.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=p13-cmac', target: '#inputs', text: 'CMAC on the RFC 4493 vectors or your own key and message: the subkeys K1 and K2, then the chain.' },
      { route: 'topic=p13-poly1305', target: '#stageWrap', text: 'Poly1305: clamp r, then one multiplication modulo 2¹³⁰ − 5 per chunk.' },
      { route: 'topic=p13-certs', target: '#stageWrap', text: 'Chain validation, check by check, for a valid chain and seven ways a chain can fail.' },
      { route: 'bench/proto', target: '#main', text: 'The protocol bench: message-sequence charts for Diffie–Hellman, Needham–Schroeder, Kerberos and TLS 1.3, with what every party knows after each message.' },
      { route: 'learn', target: '[data-chapter="mc-mac"]', text: 'The lessons and exercises of this part start here: ipad and opad blocks, CMAC subkeys, Poly1305 chunks, HKDF blocks, HMAC and HKDF in code, and certificate chains to validate.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'mc-course', title: 'MACs, key establishment and protocols', blurb: 'All fifteen topics of part 13, from the forgery game to the TLS 1.3 key schedule, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'p13-macgame', note: 'What a MAC must withstand.' },
      { topic: 'p13-hmac', note: 'ipad, opad and two hashes.' },
      { lesson: 'mc-hmac', note: 'Why HMAC is built this way.' },
      { exercise: 'mc-x-code-hmac', note: 'Write HMAC-SHA-256 and test it on RFC 4231.' },
      { topic: 'p13-cbcmac', note: 'CBC-MAC, safe only for one length.' },
      { topic: 'p13-cmac', note: 'CMAC’s subkeys.' },
      { exercise: 'mc-x-cmac-subkeys', note: 'Compute K1 and K2.' },
      { topic: 'p13-gmac', note: 'A polynomial in H.' },
      { topic: 'p13-poly1305', note: 'Clamping and the accumulator.' },
      { exercise: 'mc-x-code-poly', note: 'Write the accumulator step.' },
      { topic: 'p13-aead', note: 'Seal and open.' },
      { lesson: 'mc-aead', note: 'Composition, and why AEAD.' },
      { topic: 'p13-hkdf', note: 'Extract, then expand.' },
      { exercise: 'mc-x-code-hkdf', note: 'Write HKDF-Expand and test it on RFC 5869.' },
      { topic: 'p13-ns', note: 'Needham–Schroeder and the replayed ticket.' },
      { exercise: 'mc-x-ns-flaw', note: 'Spot the flaw.' },
      { topic: 'p13-kerberos', note: 'Tickets and timestamps.' },
      { topic: 'p13-dh', note: 'Diffie–Hellman, and a man in the middle.' },
      { topic: 'p13-authdh', note: 'Signed shares catch him.' },
      { exercise: 'mc-x-mitm', note: 'What is missing.' },
      { topic: 'p13-certs', note: 'Chains, check by check.' },
      { exercise: 'mc-x-cert-leaf', note: 'Find the failing certificate.' },
      { topic: 'p13-tls', note: 'The TLS 1.3 handshake.' },
      { topic: 'p13-tls-keys', note: 'The key schedule as a tree.' },
      { lesson: 'mc-tls', note: 'Everything together, in one round trip.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson mc-game')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.part === 'protocols').flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['mc-x-ipad', 'mc-x-code-hmac', 'mc-x-cmac-subkeys', 'mc-x-clamp', 'mc-x-code-poly', 'mc-x-hkdf-t1', 'mc-x-code-hkdf', 'mc-x-kerb-who', 'mc-x-cert-root', 'mc-x-cert-leaf', 'mc-x-tls-nonce'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course mc-course', hash: 'course=mc-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
