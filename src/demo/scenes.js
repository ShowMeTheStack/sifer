// The sample scenes of the demo page, and the data they share. Every value a scene shows comes from the engines
// in src/core, run on our own plaintexts and keys below.
(function (S) {
  'use strict';
  const D = (S.Demo = { scenes: [] });
  const { utf8 } = S.bytes;
  D.add = (scene) => { D.scenes.push(scene); D.scenes.sort((a, b) => a.order - b.order); };
  D.byId = (id) => D.scenes.find((s) => s.id === id);
  // our own data: nothing here comes from a book or a standard's examples
  D.data = {
    aesKey: utf8('ochre-river-2026'),
    aesPlain: utf8('Lanterns at dusk'),
    desKey: utf8('kestrel!'),
    desPlain: utf8('tidepool'),
    modesKey: utf8('saffron-harbour9'),
    modesIv: utf8('quiet-iv-rowan-7'),
    modesNonce: S.bytes.fromHex('5f1a7c3e9b2d4f60' + '0000000000000000'),
    modesPlain: utf8('Ferns unfurl at dawn; the tide keeps its counsel.').slice(0, 48),
    chachaKey: utf8('a lantern keeper guards 32 bytes'),
    chachaNonce: utf8('salt-marsh:7'),
    shaMsg: utf8('Sifer hashes this line, one round at a time.'),
    keccakMsg: utf8('keccak sees all'),
  };
  /** a box {x, y, w, h} */
  D.box = (x, y, w, h) => ({ x, y, w, h });
})(globalThis.Sifer = globalThis.Sifer || {});
