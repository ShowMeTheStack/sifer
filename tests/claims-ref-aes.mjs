// An independent AES for the narration checks of parts 5 and 6: written here from the definitions, apart from the
// engines in src/core (the S-box by searching for each inverse and the rotation form of the affine map, MixColumns
// with xtime written out, the key schedule from the words), and itself checked against node:crypto on load.
import { createCipheriv, createDecipheriv } from 'node:crypto';

export const xt = (a) => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 255;
/** a·b in GF(2^8) by shift and add */
export function gmul(a, b) { let r = 0; for (let i = 0; i < 8; i++) { if (b & 1) r ^= a; a = xt(a); b >>= 1; } return r; }
const rotl8 = (x, n) => ((x << n) | (x >> (8 - n))) & 255;
export const INV = new Array(256).fill(0);
for (let a = 1; a < 256; a++) for (let b = 1; b < 256; b++) if (gmul(a, b) === 1) { INV[a] = b; break; }
export const SBOX = INV.map((b) => b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63);
export const ISBOX = new Array(256); SBOX.forEach((v, i) => { ISBOX[v] = i; });

export function expand(key) {
  const Nk = key.length / 4, Nr = Nk + 6, w = [];
  for (let i = 0; i < Nk; i++) w.push([...key.slice(4 * i, 4 * i + 4)]);
  let rc = 1;
  for (let i = Nk; i < 4 * (Nr + 1); i++) {
    let t = w[i - 1].slice();
    if (i % Nk === 0) { t = [SBOX[t[1]] ^ rc, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]; rc = xt(rc); }
    else if (Nk > 6 && i % Nk === 4) t = t.map((b) => SBOX[b]);
    w.push(w[i - Nk].map((b, k) => b ^ t[k]));
  }
  return { w, Nk, Nr };
}
export const roundKey = (w, r) => w.slice(4 * r, 4 * r + 4).flat();
export const subBytes = (s) => s.map((b) => SBOX[b]);
export const invSubBytes = (s) => s.map((b) => ISBOX[b]);
export const shiftRows = (s) => s.map((_, i) => s[(i % 4) + 4 * ((Math.floor(i / 4) + (i % 4)) % 4)]);
export const invShiftRows = (s) => s.map((_, i) => s[(i % 4) + 4 * ((Math.floor(i / 4) - (i % 4) + 4) % 4)]);
export function mixColumn([a, b, c, d]) {
  return [xt(a) ^ xt(b) ^ b ^ c ^ d, a ^ xt(b) ^ xt(c) ^ c ^ d, a ^ b ^ xt(c) ^ xt(d) ^ d, xt(a) ^ a ^ b ^ c ^ xt(d)];
}
export function invMixColumn(col) {
  const M = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]];
  return M.map((row) => row.reduce((acc, m, k) => acc ^ gmul(m, col[k]), 0));
}
const byCols = (s, f) => [0, 1, 2, 3].flatMap((c) => f(s.slice(4 * c, 4 * c + 4)));
export const mixColumns = (s) => byCols(s, mixColumn);
export const invMixColumns = (s) => byCols(s, invMixColumn);
export const xorB = (a, b) => a.map((v, i) => v ^ b[i]);

/** encryption with every state: rounds[r] = {start, sub, shift, mix, key, end} */
export function encrypt(block, key) {
  const { w, Nr } = expand([...key]);
  let s = xorB([...block], roundKey(w, 0));
  const rounds = [{ round: 0, start: [...block], key: roundKey(w, 0), end: s }];
  for (let r = 1; r <= Nr; r++) {
    const sub = subBytes(s), shift = shiftRows(sub), mix = r < Nr ? mixColumns(shift) : null, k = roundKey(w, r), end = xorB(mix || shift, k);
    rounds.push({ round: r, start: s, sub, shift, mix, key: k, end });
    s = end;
  }
  return { out: s, rounds, w, Nr };
}
/** the inverse cipher with every state: rounds in the order they are undone */
export function decrypt(block, key) {
  const { w, Nr } = expand([...key]);
  let s = xorB([...block], roundKey(w, Nr));
  const rounds = [{ round: Nr, start: [...block], key: roundKey(w, Nr), end: s }];
  for (let r = Nr - 1; r >= 0; r--) {
    const shift = invShiftRows(s), sub = invSubBytes(shift), k = roundKey(w, r), added = xorB(sub, k), mix = r > 0 ? invMixColumns(added) : null;
    rounds.push({ round: r, start: s, shift, sub, key: k, added, mix, end: mix || added });
    s = mix || added;
  }
  return { out: s, rounds };
}
/** node:crypto's AES on one block, as a check of the reference itself and of final results */
export function nodeEncrypt(block, key) { const c = createCipheriv('aes-' + key.length * 8 + '-ecb', Buffer.from(key), null); c.setAutoPadding(false); return [...Buffer.concat([c.update(Buffer.from(block)), c.final()])]; }
export function nodeDecrypt(block, key) { const c = createDecipheriv('aes-' + key.length * 8 + '-ecb', Buffer.from(key), null); c.setAutoPadding(false); return [...Buffer.concat([c.update(Buffer.from(block)), c.final()])]; }

// the reference must agree with node:crypto before it is trusted
for (const n of [16, 24, 32]) for (let k = 0; k < 4; k++) {
  const key = Array.from({ length: n }, (_, i) => (i * 37 + k * 11 + n) & 255), p = Array.from({ length: 16 }, (_, i) => (i * 91 + k * 7) & 255);
  const a = encrypt(p, key).out, b = nodeEncrypt(p, key);
  if (a.join() !== b.join()) throw new Error('the reference AES disagrees with node:crypto at ' + n * 8 + ' bits');
  if (decrypt(a, key).out.join() !== p.join()) throw new Error('the reference inverse cipher fails at ' + n * 8 + ' bits');
}
