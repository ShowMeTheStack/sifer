// The CTF ladder: the rungs in order, a challenge's story and data, the flag format, wrong and right
// flags, hints and what they cost, the scoreboard, progress kept across a reload, a reset, and the phone layout.
import { assert } from '../lib.mjs';

const submit = async (p, flag) => { await p.setValue('#ctfFlag', flag); await p.click('#ctfSubmit'); return p.text('#ctfResult'); };

export default function (t) {
  t.test('the ladder lists the rungs in order', async (p) => {
    await p.route('ctf');
    const ids = await p.ev("[...document.querySelectorAll('#ctfLadder .ctf-rung')].map(a => a.dataset.challenge)");
    assert.deepEqual(ids, await p.ev('Sifer.Content.ladder().map((x) => x.id)'));
    assert.ok(ids.length >= 10 && ids[0] === 'cl-ctf-ferry-note', 'the ladder starts at the classical rungs');
    assert.ok(!(await p.ev('Sifer.Content.ladder().some((x) => x.sample)')), 'no placeholder rungs');
    // rungs are numbered 1, 2, 3, … down the whole ladder, whichever parts the challenges come from
    assert.deepEqual(await p.ev("[...document.querySelectorAll('#ctfLadder .cr-n')].map(e => +e.textContent)"), ids.map((_, i) => i + 1));
    assert.ok(await p.exists('.ctf-rung.next[data-challenge="' + ids[0] + '"]'), 'the first rung is next');
    const total = await p.ev('Sifer.Content.ladder().reduce((s, x) => s + x.points, 0)');
    assert.match(await p.text('#ctfScore'), new RegExp('0\\s*points of ' + total.toLocaleString('en-GB').replace(/,/g, ',?')));
  });

  t.test('wrong format, wrong flag, then the right one; the scoreboard follows', async (p) => {
    await p.route('ctf/cl-ctf-ferry-note');
    assert.match(await p.text('#ctfChallenge'), /night clerk|ferry/i);
    assert.match(await p.text('.ctf-data'), /^[A-Z .,'\n-]{40,}/);
    let r = await submit(p, 'tide tables');
    assert.match(r, /not a flag: a flag looks like sifer\{\.\.\.\}/);
    r = await submit(p, 'sifer{tide_tables}');
    assert.match(r, /format is right, but this is not the flag/);
    assert.ok(!(await p.visible('#ctfSolvedTag')));
    r = await submit(p, 'SIFER{TIDE_TABLES_NEVER_LIE}');
    assert.match(r, /Captured/, 'this rung takes the flag in either case');
    assert.match(await p.text('#ctfSolvedTag'), /Solved for 200 points/);
    await p.click('#ctfNext');
    await p.wait("location.hash === '#ctf/cl-ctf-desk-letter'");
    await p.route('ctf');
    assert.ok(await p.exists('.ctf-rung.solved[data-challenge="cl-ctf-ferry-note"]'));
    assert.ok(await p.exists('.ctf-rung.next[data-challenge="cl-ctf-desk-letter"]'));
    assert.equal(await p.text('#ctfPoints'), '200');
    assert.equal(await p.text('#ctfSolved'), '1 / ' + (await p.ev('Sifer.Content.ladder().length')));
  });

  t.test('hints come one at a time, the last after a question, and cost points', async (p) => {
    await p.route('ctf/num-ctf-clocks');
    assert.match(await p.text('#ctfHint'), /Hint 1 of 3/);
    await p.click('#ctfHint');
    await p.click('#ctfHint');
    assert.equal(await p.count('#ctfHintList .hint'), 2);
    await p.click('#ctfHint');
    assert.equal(await p.waitModal(), 'Take the last hint?');
    await p.modalButton('Show it');
    assert.equal(await p.count('#ctfHintList .hint'), 3);
    assert.ok(await p.ev("document.getElementById('ctfHint').disabled"));
    const r = await submit(p, 'sifer{hands_meet_once}');
    assert.match(r, /Captured/);
    assert.match(await p.text('#ctfSolvedTag'), /Solved for 100 points/, 'half of 200 after all three hints');
    await p.route('ctf');
    assert.equal(await p.text('#ctfHints'), '3');
  });

  t.test('the data copies, a flag is case-sensitive where the rung says so, progress survives a reload and can be reset', async (p) => {
    await p.route('ctf/cl-ctf-two-pads');
    assert.ok(await p.exists('.ctf-data .icon-btn.copy'));
    assert.match(await submit(p, 'sifer{ONE_PAD_TWO_MESSAGES}'), /format is right, but this is not the flag/);
    assert.match(await submit(p, 'sifer{one_pad_two_messages}'), /Captured/);
    await p.reload();
    await p.route('ctf');
    assert.equal(await p.text('#ctfSolved'), '1 / ' + (await p.ev('Sifer.Content.ladder().length')));
    await p.click('#ctfReset');
    await p.waitModal();
    await p.modalButton('Reset');
    await p.wait("document.getElementById('ctfSolved') && document.getElementById('ctfSolved').textContent === '0 / ' + Sifer.Content.ladder().length");
    assert.equal(await p.text('#ctfPoints'), '0');
  }, { fresh: true });

  t.test('a missing challenge says so, and the pages fit a phone', async (p) => {
    await p.route('ctf/no-such-rung');
    assert.match(await p.text('#main'), /no challenge called/);
    await p.viewport(390, 844, { mobile: true, touch: true });
    for (const h of ['ctf', 'ctf/cl-ctf-two-pads', 'ctf/num-ctf-impostor']) { await p.route(h); assert.ok(await p.noHScroll(), h); }
    await p.viewport(1400, 900);
  });
}
