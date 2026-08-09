// The curve explorer: clicking two points of a real curve gives their sum (checked against the engine), doubling by
// the tangent, the sliders; over GF(p) the cloud has every point, two clicks add, k·P by double-and-add and by the
// ladder agree with the engine, Hasse's bound holds; and the explorer fits a phone.
import { assert } from '../lib.mjs';

const tool = async (p, t) => { await p.click('#cv-tool button[data-v="' + t + '"]'); await p.wait("!!document.querySelector('#cvOut svg.cv-svg')"); };
const view = 'Sifer.app.page.bench.view';
const clickPlot = async (p, x, y) => { await p.ev("document.querySelector('#cvOut svg.cv-svg').scrollIntoView({ block: 'center' })"); await p.sleep(60); const [cx, cy] = await p.ev(`${view}.screen(${x}, ${y})`); await p.clickAt(cx, cy, { after: 150 }); };
const f2 = (v) => (Math.abs(v) < 0.005 ? '0.00' : v.toFixed(2)).replace('-', '−');

export default function (t) {
  t.test('over the reals: two clicks on the curve, and the chord finds P + Q', async (p) => {
    await p.route('bench/curve');
    await tool(p, 'real');
    await p.click('#cvMode button[data-v="add"]');
    await p.click('.mb-ex .chip', 'two branches');
    await p.sleep(100);
    const y1 = await p.ev('Math.max(...Sifer.EC.real(-2, 2).ys(-1.25))'), y2 = await p.ev('Math.max(...Sifer.EC.real(-2, 2).ys(1.5))');
    await clickPlot(p, -1.25, y1);
    assert.match(await p.text('#cvHint'), /place Q/);
    await clickPlot(p, 1.5, y2);
    const R = await p.ev(`Sifer.EC.real(-2, 2).add({ x: -1.25, y: ${y1} }, { x: 1.5, y: ${y2} }).R`);
    assert.match(await p.text('#cvRealInfo'), new RegExp('P \\+ Q\\s+\\(' + f2(R.x) + ', ' + f2(R.y) + '\\)'));
    assert.equal(await p.count('#cvRealStage .cv-pt'), 4, 'P, Q, the third point and the sum');
    assert.ok(await p.exists('#cvRealStage .cv-line'), 'the chord');
    assert.ok(await p.exists('#cvRealStage .cv-mirror'), 'the mirror');
  });

  t.test('doubling by the tangent, a vertical line gives O, and the sliders move the curve', async (p) => {
    await p.route('bench/curve');
    await tool(p, 'real');
    await p.click('#cvMode button[data-v="double"]');
    const y = await p.ev('Math.max(...Sifer.EC.real(-2, 2).ys(1))');
    await clickPlot(p, 1, y);
    const R = await p.ev(`Sifer.EC.real(-2, 2).add({ x: 1, y: ${y} }, { x: 1, y: ${y} }).R`);
    assert.match(await p.text('#cvRealInfo'), new RegExp('2P\\s+\\(' + f2(R.x) + ', ' + f2(R.y) + '\\)'));
    await p.click('#cvMode button[data-v="add"]');
    const yq = await p.ev('Math.max(...Sifer.EC.real(-2, 2).ys(0.5))');
    await clickPlot(p, 0.5, yq); await clickPlot(p, 0.5, -yq);
    assert.match(await p.text('#cvRealInfo'), /the point at infinity/);
    await p.setValue('#cvA', '0', 'input');
    await p.setValue('#cvB', '0', 'input');
    await p.sleep(100);
    assert.match(await p.text('#cvRealInfo'), /singular/);
    await p.click('.mb-ex .chip', 'two branches');
  });

  t.test('over GF(p): every point drawn, two clicks add, k·P both ways, Hasse\'s bound', async (p) => {
    await p.route('bench/curve');
    await tool(p, 'field');
    await p.setValue('#cvToy', 'gf101', 'change');
    await p.sleep(200);
    const n = await p.ev('Sifer.ECC.toy("gf101").points().length');
    assert.equal(await p.count('#cvFieldStage .cv-dot'), n);
    assert.match(await p.text('#cvFieldInfo'), new RegExp('#E\\s+' + (n + 1) + ' \\(' + n + ' points and O\\)'));
    const [a, b] = JSON.parse(await p.ev('JSON.stringify(Sifer.ECC.toy("gf101").points().slice(4, 30).filter((_, i) => i === 0 || i === 25).map((q) => [Number(q.x), Number(q.y)]))'));
    await clickPlot(p, a[0], a[1]);
    assert.match(await p.text('#cvFhint'), /choose Q/);
    await clickPlot(p, b[0], b[1]);
    const R = await p.ev(`(() => { const C = Sifer.ECC.toy('gf101'), R = C.add({ x: ${a[0]}n, y: ${a[1]}n }, { x: ${b[0]}n, y: ${b[1]}n }); return R ? '(' + R.x + ', ' + R.y + ')' : 'O'; })()`);
    assert.match(await p.text('#cvLegend'), new RegExp('P \\+ Q = ' + R.replace(/[()]/g, '\\$&')));
    await p.setValue('#cvK', '13'); await p.sleep(400);
    const K = await p.ev(`(() => { const C = Sifer.ECC.toy('gf101'), R = C.mul(13n, { x: ${a[0]}n, y: ${a[1]}n }); return R ? '(' + R.x + ', ' + R.y + ')' : 'O'; })()`);
    assert.match(await p.text('#cvFieldInfo'), new RegExp('k·P\\s+' + K.replace(/[()]/g, '\\$&')));
    await p.click('#cvAlg button[data-v="ladder"]');
    await p.sleep(150);
    assert.match(await p.text('#cvFieldInfo'), new RegExp('k·P\\s+' + K.replace(/[()]/g, '\\$&')));
    assert.match(await p.text('#cvFieldInfo'), /Montgomery ladder/);
    await p.click('#cvWalkStep button[title="Only the first row"]');
    await p.sleep(150);
    assert.match(await p.text('#cvWalkStep'), /step 1 of/);
    const [lo, hi] = await p.ev('(() => { const h = Sifer.ECC.toy("gf101").hasse(); return [Number(h.lo), Number(h.hi)]; })()');
    assert.ok(lo <= n + 1 && n + 1 <= hi, 'Hasse');
  });

  t.test('a curve of my own, refused when singular or not over a prime, and phone width', async (p) => {
    await p.route('bench/curve');
    await tool(p, 'field');
    await p.setValue('#cvToy', 'custom', 'change');
    await p.setValue('#cvFp', '91'); await p.sleep(400);
    assert.match(await p.text('#cvFieldInfo .berr'), /not prime/);
    await p.setValue('#cvFp', '23'); await p.setValue('#cvFa', '0'); await p.setValue('#cvFb', '0'); await p.sleep(400);
    assert.match(await p.text('#cvFieldInfo .berr'), /singular/);
    await p.setValue('#cvFb', '1'); await p.sleep(400);
    const n = await p.ev('Sifer.ECC.curve({ p: 23n, a: 0n, b: 1n }).points().length');
    assert.equal(await p.count('#cvFieldStage .cv-dot'), n);
    await p.setValue('#cvToy', 'gf101', 'change');
    await p.viewport(390, 844, { mobile: true, touch: true });
    for (const t2 of ['real', 'field']) { await tool(p, t2); await p.sleep(200); assert.ok(await p.noHScroll(), t2 + ' scrolls sideways at 390 px'); }
    await p.viewport(1400, 900);
  });
}
