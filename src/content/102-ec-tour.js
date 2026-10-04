// Part 10, elliptic curves: the guided tour and the course, and the pages the diagram checker looks at. The attacks on
// the logarithm and on careless code appear only as the reasons for the rules: a prime-order group, cofactor handling,
// point validation, a safe twist and a well-chosen curve.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.tours.has('ecc-tour')) return;

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'ecc-tour', title: 'Tour: elliptic curves', blurb: 'From chord and tangent to X25519, and the rules that keep a curve safe, in eight steps.',
    steps: [
      { route: 'part=ecc', target: '#main', text: 'Part 10 of the catalogue: elliptic curves. Every topic runs on real numbers, on toy fields you can check by hand, and on P-256 and Curve25519.' },
      { route: 'topic=ec-real-add', target: '#stageWrap', text: 'The group law: the line through P and Q meets the curve at a third point, and its mirror image is P + Q. The tangent doubles a point.' },
      { target: '#btnPlay', text: 'Play steps through the construction; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=ec-gfp-law', target: '#stageWrap', text: 'The same formulas modulo a prime: a cloud of points, lines that wrap round the grid, and division done with an inverse.' },
      { route: 'topic=ec-ladder', target: '#inputs', text: 'k·P by the Montgomery ladder: one addition and one doubling for every bit, so the work says nothing about the key. Try another k here.' },
      { route: 'topic=ec-invalid', target: '#stageWrap', text: 'Why every received point is validated: the formulas never use b, so an unchecked point is processed on another curve. The last step shows the one check that stops it.' },
      { route: 'lesson=ecc-validate', target: '#lessonView', text: 'Lessons run the topics, ask for a prediction, and end with exercises. This one writes point validation and matches each check to the input it rejects.' },
      { route: 'learn', target: '[data-chapter="ecc-ch-law"]', text: 'The lessons and exercises of this part start here: add and double points by hand, run double-and-add and the ladder, agree an ECDH key, write the code, and choose a curve.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'ecc-course', title: 'Elliptic curves', blurb: 'All twenty-one topics of part 10, from the group law to the rules for choosing a curve, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'ec-real-shape', note: 'The shape of the curve, and the singular ones to avoid.' },
      { topic: 'ec-real-add', note: 'Chord and tangent.' },
      { lesson: 'ecc-real', note: 'Chord and tangent.' },
      { topic: 'ec-gfp-law', note: 'The same formulas modulo p.' },
      { topic: 'ec-infinity', note: 'The point at infinity.' },
      { lesson: 'ecc-gfp', note: 'The group law mod p.' },
      { exercise: 'ecc-x-add', note: 'Add two points by hand.' },
      { topic: 'ec-order', note: 'The order of a point, and the shape of the group.' },
      { lesson: 'ecc-order', note: 'Orders and Lagrange.' },
      { topic: 'ec-hasse', note: 'Counting points; Hasse\'s bound.' },
      { exercise: 'ecc-x-count', note: 'Count a curve by hand.' },
      { topic: 'ec-double-add', note: 'Double-and-add.' },
      { lesson: 'ecc-dbladd', note: 'Double-and-add.' },
      { exercise: 'ecc-x-dbladd-table', note: 'Bit by bit.' },
      { topic: 'ec-ladder', note: 'The Montgomery ladder.' },
      { lesson: 'ecc-ladder', note: 'The same work for every bit.' },
      { topic: 'ec-wnaf', note: 'Signed digits.' },
      { topic: 'ec-jacobian', note: 'Jacobian coordinates and the cost of k·P.' },
      { topic: 'ec-ecdh', note: 'ECDH on a toy curve and on P-256.' },
      { topic: 'ec-x25519', note: 'X25519: clamping and the ladder.' },
      { lesson: 'ecc-ecdh', note: 'Key exchange.' },
      { exercise: 'ecc-x-ecdh', note: 'A shared point by hand.' },
      { topic: 'ec-forms', note: 'Three shapes of one curve.' },
      { topic: 'ec-compress', note: 'Point compression, and rejecting an x with no point.' },
      { lesson: 'ecc-shapes', note: 'Shapes and encodings.' },
      { topic: 'ec-bsgs', note: 'Why √n sets the size: baby-step giant-step.' },
      { topic: 'ec-rho', note: 'The same √n with no memory: rho.' },
      { topic: 'ec-pohlig', note: 'Why the order must be prime.' },
      { lesson: 'ecc-size', note: 'A large group of prime order.' },
      { topic: 'ec-invalid', note: 'Why points are validated.' },
      { topic: 'ec-twist', note: 'Why the twist must be safe.' },
      { lesson: 'ecc-validate', note: 'Validate every point.' },
      { exercise: 'ecc-x-code-valid', note: 'Write the checks.' },
      { topic: 'ec-smart', note: 'A prime order is not enough: #E ≠ p.' },
      { topic: 'ec-curve-choice', note: 'P-256 against Curve25519.' },
      { lesson: 'ecc-choose', note: 'Choosing a curve.' },
      { exercise: 'ecc-x-choose', note: 'Choose for a device.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson ecc-real')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.id.startsWith('ecc-')).flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['ecc-x-add', 'ecc-x-dbl', 'ecc-x-code-add', 'ecc-x-dbladd-table', 'ecc-x-ladder-table', 'ecc-x-leak', 'ecc-x-ecdh', 'ecc-x-clamp', 'ecc-x-decompress', 'ecc-x-checks', 'ecc-x-code-valid', 'ecc-x-choose'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course ecc-course', hash: 'course=ecc-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
