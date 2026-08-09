// Topics, lessons, exercises and courses: the framework, driven with content registered by the test itself (the
// course's own content arrives later). A small topic runs in the player with a prediction and a quiz; a lesson shows
// its blocks; every answer kind is checked right and wrong in the page, the code kind in its sandboxed worker.
import { assert } from '../lib.mjs';

const SETUP = `(() => {
  const S = Sifer, C = S.Content;
  if (!S.byId('zz-count')) {
    S.family({ id: 'zz-fam', part: 'numbers', title: 'Counting test', blurb: 'A family for the test.' });
    S.topic({ id: 'zz-count', family: 'zz-fam', title: 'Counting mod n', blurb: 'Steps round a clock.',
      inputs: [{ id: 'n', kind: 'number', label: 'n', def: 5, min: 2, max: 12 }],
      presets: [{ label: 'n = 7', values: { n: 7 } }],
      run(inp) { const fr = []; for (let k = 0; k <= inp.n; k++) fr.push({ items: [{ kind: 'cell', key: 'c', x: 0, y: 0, w: 60, h: 40, text: String(k % inp.n) }, { kind: 'text', key: 't', x: 30, y: 70, text: 'step ' + k, anchor: 'middle' }], say: 'Step ' + k + ': ' + k + ' mod ' + inp.n + ' is ' + (k % inp.n) + '.' }); return fr; },
      predict: [{ at: (f, i) => i === 2, ask: 'What comes next?', options: ['3', '4'], answer: '3' }],
      quiz: [0, 1, 2, 3].map((i) => ({ q: 'Question ' + i, options: ['a', 'b'], answer: 0, why: 'Because.' })) });
  }
  if (!C.chapters.some((c) => c.id === 'zz')) {
    C.chapter({ id: 'zz', part: 'numbers', title: 'Test chapter', blurb: 'For the test.' });
    C.lesson({ id: 'zz-l', chapter: 'zz', title: 'A test lesson', minutes: 3, summary: 'With **every** block.', blocks: ['A paragraph with \`code\`.', { h: 'A heading' }, { bytes: { hex: '00112233', hl: [1], label: 'Four bytes' }, caption: 'bytes' }, { predict: { q: 'Pick b', options: ['a', 'b'], answer: 1, explain: 'It is b.' } }, { topic: 'zz-count' }, { exercise: 'zz-hex' }] });
    C.exercise({ id: 'zz-hex', chapter: 'zz', title: 'A hex answer', kind: 'hex', text: ['Give ae.'], hints: ['h1', 'h2', 'worked'], answer: 'ae', solution: 'ae', wrong: ['af'] });
    C.exercise({ id: 'zz-code', chapter: 'zz', title: 'A code answer', kind: 'code', fn: 'add', params: ['a', 'b'], text: ['Add.'], hints: ['h1', 'h2', 'worked'], tests: [{ args: [1n, 2n], want: 3n }, { args: [5n, 5n], want: 10n }], solution: 'function add(a, b) { return a + b; }', wrong: ['function add(a, b) { return a; }'] });
    C.exercise({ id: 'zz-flag', chapter: 'zz', title: 'A flag', kind: 'flag', format: 'sifer{...}', flagHash: S.Check.flagHash('sifer{ok}'), text: ['Flag.'], hints: ['h1', 'h2', 'worked'], solution: 'sifer{ok}', wrong: ['x'] });
    C.exercise({ id: 'zz-break', chapter: 'zz', title: 'Break it', kind: 'break', target: 'shift', normalize: 'int', answer: 3, data: { Ciphertext: 'PHHW' }, text: ['Find the shift.'], hints: ['h1', 'h2', 'worked'], solution: '3', wrong: ['4'] });
    C.exercise({ id: 'zz-state', chapter: 'zz', title: 'Fill the state', kind: 'table', table: 'state', state: '00112233445566778899aabbccddeeff', give: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13], text: ['Fill.'], hints: ['h1', 'h2', 'worked'], solution: {}, wrong: [] });
    C.exercise({ id: 'zz-choice', chapter: 'zz', title: 'Choose', kind: 'choice', options: ['ECB', 'CBC'], answer: 1, text: ['Which hides patterns?'], hints: ['h1', 'h2', 'worked'], solution: 1, wrong: [0] });
    C.course({ id: 'zz-course', title: 'Test course', blurb: 'Three steps.', steps: ['zz-count', { lesson: 'zz-l', note: 'Read it.' }, { exercise: 'zz-hex' }] });
  }
  return 1;
})()`;

export default function (t) {
  t.beforeEach(async (p) => { await p.ev(SETUP); });

  t.test('the topics catalogue lists the parts and the test topic', async (p) => {
    await p.route('topics');
    assert.equal(await p.count('#topicsView section.part'), 15);
    assert.ok(await p.exists('#topicsView a[data-topic="zz-count"]'));
    await p.route('part=numbers');
    assert.ok(await p.exists('#part-numbers'));
  });

  t.test('a topic runs: steps, a prediction, a preset, the quiz', async (p) => {
    await p.route('topic=zz-count');
    await p.wait('Sifer.app.page.player && Sifer.app.page.player.frames.length === 6');
    assert.match(await p.text('#say'), /0 mod 5/);
    await p.click('#btnFwd'); await p.click('#btnFwd');
    await p.click('#btnFwd');
    assert.ok(await p.exists('#predict'), 'the prediction stops the player');
    await p.click('#predict .chip', '3');
    assert.match(await p.text('#predict'), /Right/);
    await p.click('#predictGo');
    assert.match(await p.text('#say'), /3 mod 5/);
    await p.click('.presets .chip', 'n = 7');
    await p.wait('Sifer.app.page.player.frames.length === 8');
    await p.click('#btnQuiz');
    assert.match(await p.waitModal(), /Quiz/);
    await p.closeModals();
  });

  t.test('the learn list, and a lesson with its blocks', async (p) => {
    await p.route('learn');
    assert.ok(await p.exists('#learnView [data-chapter="zz"]'));
    await p.route('lesson=zz-l');
    assert.ok(await p.exists('#lessonView .byte-grid .bg-b.hl'), 'bytes block');
    await p.click('.ls-predict .quiz-opt', 'b');
    assert.match(await p.text('.lp-res'), /Right/);
    assert.ok(await p.exists('#lessonView .topic.embed .stage-svg'), 'a live topic');
    assert.ok(await p.exists('.ls-link[href="#exercise=zz-hex"]'));
    await p.click('#lessonDone');
    await p.wait("location.hash === '#exercise=zz-hex'");
  });

  t.test('hex, flag, break and choice answers are checked right and wrong', async (p) => {
    await p.route('exercise=zz-hex');
    await p.setValue('#ansText', 'af');
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.bad')");
    assert.match(await p.text('#exResult'), /1 byte differs/);
    await p.setValue('#ansText', '0xAE');
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.ok')");
    await p.route('exercise=zz-flag');
    await p.setValue('#ansText', 'ok');
    await p.click('#btnCheck');
    await p.wait("/looks like sifer/.test(document.querySelector('#exResult').innerText)");
    await p.setValue('#ansText', 'sifer{ok}');
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.ok')");
    await p.route('exercise=zz-break');
    assert.match(await p.text('.break-data'), /PHHW/);
    await p.setValue('#ansText', '3');
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.ok')");
    await p.route('exercise=zz-choice');
    await p.click('.quiz-opt.choice', 'CBC');
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.ok')");
  });

  t.test('a code answer runs in the sandboxed worker, with the failing case shown', async (p) => {
    await p.route('exercise=zz-code');
    await p.setValue('#ansCode', 'function add(a, b) { return a; }');
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.bad')", 8000);
    assert.match(await p.text('#exResult'), /Test 1 of 2 fails: add\(1n, 2n\) returned 1n, but it should return 3n/);
    assert.ok(await p.exists('.cases-table tr.fail'));
    await p.setValue('#ansCode', 'function add(a, b) { console.log("adding", a, b); return a + b; }');
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.ok')", 8000);
    assert.match(await p.text('details.logs'), /adding 1n 2n/);
    await p.setValue('#ansCode', 'function add(a, b) { for (;;) {} }');
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.bad')", 8000);
    assert.match(await p.text('#exResult'), /ran longer than 2 s/);
  });

  t.test('a state to fill, cell by cell; hints one at a time', async (p) => {
    await p.route('exercise=zz-state');
    assert.equal(await p.count('.state-fill input'), 2);
    await p.ev("[...document.querySelectorAll('.state-fill input')].forEach((i, k) => { i.value = ['ee', 'ff'][k]; })");
    await p.click('#btnCheck');
    await p.wait("document.querySelector('#exResult.ok')");
    await p.click('#btnHint');
    assert.match(await p.text('#hints'), /Hint 1/);
  });

  t.test('a course walks its steps', async (p) => {
    await p.route('courses');
    assert.ok(await p.exists('[data-course="zz-course"]'));
    await p.route('course=zz-course');
    await p.click('#courseStart');
    await p.wait("location.hash === '#course=zz-course/0'");
    assert.ok(await p.exists('#courseStrip'));
    await p.click('#courseNext');
    await p.wait("location.hash === '#course=zz-course/1' && !!document.querySelector('#lessonView')");
  });
}
