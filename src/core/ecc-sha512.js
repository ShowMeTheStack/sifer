// SHA-512 (FIPS 180-4) for Ed25519, on 64-bit BigInt words. When the hash engines provide SHA-512 (S.Hash) that one is used;
// this compact version is the fallback, so the signature engine never depends on load order.
//   S.ECC.sha512(bytes) -> 64 bytes
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const M64 = (1n << 64n) - 1n;
  const K = [
    '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc', '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
    'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2', '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
    'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65', '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
    '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4', 'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
    '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df', '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
    'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30', 'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
    '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8', '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
    '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec', '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
    'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178', '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
    '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c', '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817',
  ].map((h) => BigInt('0x' + h));
  const IV = ['6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1', '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179'].map((h) => BigInt('0x' + h));
  const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M64;

  const local = (msg) => {
    const len = msg.length, total = Math.ceil((len + 17) / 128) * 128, m = new Uint8Array(total);
    m.set(msg); m[len] = 0x80;
    let bits = BigInt(len) * 8n;
    for (let i = total - 1; bits > 0n; i--, bits >>= 8n) m[i] = Number(bits & 255n);
    const H = IV.slice(), W = new Array(80);
    for (let off = 0; off < total; off += 128) {
      for (let t = 0; t < 16; t++) { let v = 0n; for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(m[off + 8 * t + j]); W[t] = v; }
      for (let t = 16; t < 80; t++) {
        const s0 = rotr(W[t - 15], 1n) ^ rotr(W[t - 15], 8n) ^ (W[t - 15] >> 7n), s1 = rotr(W[t - 2], 19n) ^ rotr(W[t - 2], 61n) ^ (W[t - 2] >> 6n);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) & M64;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let t = 0; t < 80; t++) {
        const T1 = (h + (rotr(e, 14n) ^ rotr(e, 18n) ^ rotr(e, 41n)) + ((e & f) ^ (~e & M64 & g)) + K[t] + W[t]) & M64;
        const T2 = ((rotr(a, 28n) ^ rotr(a, 34n) ^ rotr(a, 39n)) + ((a & b) ^ (a & c) ^ (b & c))) & M64;
        h = g; g = f; f = e; e = (d + T1) & M64; d = c; c = b; b = a; a = (T1 + T2) & M64;
      }
      [a, b, c, d, e, f, g, h].forEach((v, i) => { H[i] = (H[i] + v) & M64; });
    }
    const out = new Uint8Array(64);
    H.forEach((v, i) => { for (let j = 7; j >= 0; j--) { out[8 * i + j] = Number(v & 255n); v >>= 8n; } });
    return out;
  };
  E.sha512Local = local;
  E.sha512 = (msg) => {
    let ext = null;
    try { ext = S.Hash && S.Hash.get && S.Hash.get('sha512').hash; } catch (e) { ext = null; }
    if (ext) { const out = ext(msg); if (out && out.length === 64) return out instanceof Uint8Array ? out : Uint8Array.from(out); }
    return local(msg);
  };
})(globalThis.Sifer = globalThis.Sifer || {});
