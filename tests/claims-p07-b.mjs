// Part 7: the claim checks of the trapdoor topic and of the topics of public keys at work, collected by
// tests/claims-p07.mjs.
import { pw, gcd, S } from './claims-lib-pk.mjs';
import { createHash, createDiffieHellman, createDecipheriv, createPrivateKey, privateDecrypt, constants } from 'node:crypto';

const sha = (s) => BigInt('0x' + createHash('sha256').update(s, 'utf8').digest('hex'));
const b64u = (v) => { let h = v.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex').toString('base64url'); };
const jwk = (k) => createPrivateKey({ key: { kty: 'RSA', n: b64u(k.n), e: b64u(k.e), d: b64u(k.d), p: b64u(k.p), q: b64u(k.q), dp: b64u(k.dp), dq: b64u(k.dq), qi: b64u(k.qinv) }, format: 'jwk' });
const words = ['pay 40 at noon', 'hi', 'the 9 tulips', 'no digits here', 'x1', 'Ünïcode ok 7', 'meet me at 12:30 by the bridge'];

const ops = (e) => { const b = BigInt(e).toString(2); return b.length - 1 + [...b].filter((c) => c === '1').length - 1; };
const gnfs = (bits) => { const ln = bits * Math.log(2); return Math.cbrt(64 / 9) * Math.cbrt(ln) * Math.log(ln) ** (2 / 3) / Math.log(2); };

export const mods = [
  {
    topic: 'p07-trapdoor', allow: ['3', '1.4', '8'],
    random: (rnd) => ({ fn: ['rsa', 'factor', 'dlog'][Math.floor(rnd() * 3)], size: ['toy', 'small', 'real'][Math.floor(rnd() * 3)] }),
    count: 9,
    check({ input, r, fail }) {
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'start' && input.fn !== 'dlog' && x.p * x.q !== x.n && input.fn !== 'factor') fail('n = p·q');
        if (ph === 'forward') {
          if (input.fn === 'factor') { if (x.n.toString(2).length !== x.bits) fail('the bit length of n'); continue; }
          if (x.sq + x.mul !== x.ops) fail('the operation count');
          const s = r.frames[0].facts;
          if (input.fn === 'rsa') { if (x.y !== pw(s.x, s.e, s.n) || x.ops !== ops(s.e)) fail('the RSA forward value or its cost'); }
          else if (x.ops !== ops(s.x)) fail('the cost of g^x');
        }
        if (ph === 'back') {
          const s = r.frames[0].facts;
          if (input.size === 'real') { const want = Math.round(gnfs(x.bits)); if (x.back !== want) fail('the number field sieve estimate ' + x.back + ' against ' + want); continue; }
          if (input.fn !== 'dlog') {
            const n = r.frames[1].facts.n;
            if (n % x.found !== 0n || x.ops !== Number((x.found - 1n) / 2n)) fail('the trial division');
            for (let d = 3n; d < x.found; d += 2n) if (n % d === 0n) { fail('a smaller factor ' + d); break; }
          }
        }
        if (ph === 'trapdoor' && x.back !== r.frames[0].facts.x) fail('the trapdoor does not give x back');
      }
      // the logarithm found really is one
      if (input.fn === 'dlog' && input.size !== 'real') {
        const b = r.frames.find((f) => f.meta.phase === 'back').facts, s = r.frames[0].facts, y = r.frames[1].facts.y;
        const p = BigInt(r.frames[0].say.match(/prime p = (\d+)/)[1]);
        if (pw(s.g, b.found, p) !== y) fail('g^found is not y');
        const n = p - 1n; let m = 1n; while (m * m < n) m++;
        if (b.m !== m) fail('the size of the baby-step table');
        if (gcd(s.g, p) !== 1n) fail('g');
      }
    },
  },
  {
    topic: 'p07-uses', allow: ['8', '9', '17'],
    random: (rnd) => ({ job: ['encrypt', 'sign', 'agree'][Math.floor(rnd() * 3)], size: rnd() < 0.5 ? 'toy' : 'real', msg: words[Math.floor(rnd() * words.length)] }),
    count: 12,
    check({ input, r, fail }) {
      const ph = (p) => r.frames.find((f) => f.meta.phase === p).facts;
      if (input.job === 'encrypt') {
        const k = ph('keys'), l = ph('lock'), o = ph('open');
        const text = input.size === 'real' ? input.msg : input.msg.slice(0, 2);
        const m = BigInt('0x' + (Buffer.from(text, 'utf8').toString('hex') || '0'));
        if (l.m !== m || l.c !== pw(m, k.e, k.n) || o.m !== m) fail('the encryption round trip');
        if (pw(pw(5n, k.e, k.n), k.d, k.n) !== 5n) fail('d does not invert e');
      } else if (input.job === 'sign') {
        const k = ph('keys'), sg = ph('sign'), v = ph('verify'), fo = ph('forge');
        if (sg.h !== sha(input.msg) % k.n || pw(sg.s, k.e, k.n) !== sg.h || v.v !== sg.h) fail('the signature');
        if (fo.h2 !== sha(fo.forged) % k.n || fo.h2 === sg.h || fo.forged === input.msg) fail('the forged message');
      } else {
        const pg = ph('params'), x = ph('secrets'), sh = ph('shared');
        if (x.A !== pw(pg.g, x.a, pg.p) || x.B !== pw(pg.g, x.b, pg.p) || sh.K !== pw(x.A, x.b, pg.p)) fail('the key agreement');
        if (input.size === 'real') {
          const hx = (v) => { let h = v.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex'); };
          const dh = createDiffieHellman(hx(pg.p), hx(pg.g)); dh.setPrivateKey(hx(x.a));
          if (BigInt('0x' + dh.computeSecret(hx(x.B)).toString('hex')) !== sh.K) fail('node:crypto disagrees on the shared secret');
        }
      }
    },
  },
  {
    topic: 'p07-levels', allow: ['3', '4', '5', '1024', '800', '57', '128', '256'],
    random: (rnd) => ({ level: ['80', '112', '128', '192', '256'][Math.floor(rnd() * 5)], rsa: 256 + Math.floor(rnd() * 16000), ecc: 64 + Math.floor(rnd() * 500) }),
    check({ input, r, fail }) {
      for (const f of r.frames) {
        const x = f.facts;
        if (f.meta.phase === 'row' && x.ratio !== Math.round(x.rsa / x.ecc)) fail('the ratio of modulus to curve');
        if (f.meta.phase === 'mine-rsa' && x.g !== Math.round(gnfs(input.rsa))) fail('the sieve estimate');
        if (f.meta.phase === 'mine-ecc' && Math.abs(x.r - (input.ecc / 2 + Math.log2(Math.sqrt(Math.PI / 4)))) > 1e-9) fail('the rho estimate');
      }
    },
  },
  {
    topic: 'p07-hybrid', allow: ['16', '128', '17', '66'],
    random: (rnd) => ({ size: ['toy', 'rsa1024', 'rsa2048'][Math.floor(rnd() * 3)], msg: words[Math.floor(rnd() * words.length)].repeat(1 + Math.floor(rnd() * 8)), seed: 1 + Math.floor(rnd() * 9999) }),
    check({ input, r, fail }) {
      const o = r.frames[0].meta.o, msg = Buffer.from(input.msg, 'utf8');
      if (o.pt !== input.msg || !o.ok) fail('the round trip');
      if (o.real) {
        const d = createDecipheriv('aes-128-gcm', Buffer.from(o.K), Buffer.from(o.iv)); d.setAuthTag(Buffer.from(o.tag));
        const pt = Buffer.concat([d.update(Buffer.from(o.ct)), d.final()]);
        if (!pt.equals(msg)) fail('node:crypto cannot open the AES-GCM data');
        let h = o.wrapped.toString(16); h = h.padStart(o.wrappedBytes * 2, '0');
        const K = privateDecrypt({ key: jwk(o.key), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(h, 'hex'));
        if (!K.equals(Buffer.from(o.K))) fail('node:crypto cannot unwrap the key');
        const k = Math.ceil(o.key.n.toString(2).length / 8);
        if (o.per !== k - 66 || o.rsaBlocks !== Math.ceil(msg.length / (k - 66)) || o.aesBlocks !== Math.ceil(msg.length / 16)) fail('the block counts');
      } else if (pw(o.wrapped, o.key.d, o.key.n) !== o.kInt) fail('the toy unwrap');
      void S;
    },
  },
];
