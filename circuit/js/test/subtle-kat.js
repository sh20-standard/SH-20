// Known answers for subtle.js, in a form that runs in Node (webcrypto.test.js) and in a browser page
// (subtle.html): no import. They come from the RFCs and the GCM specification, and two from OpenSSL
// through node:crypto for the sizes SPEC-NOTES uses; webcrypto.test.js recomputes every one of them
// with node:crypto, so a wrong constant here fails there.

const h = (s) => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const text = (s) => new TextEncoder().encode(s);
const fill = (n, byte) => new Uint8Array(n).fill(byte);

export const KAT = Object.freeze({
  sha256: { data: text('abc'), want: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
  // RFC 4231, test case 1
  hmacSha512: { key: fill(20, 0x0b), data: text('Hi There'), want: '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854' },
  hkdf: [
    // RFC 5869, test case 1
    { salt: h('000102030405060708090a0b0c'), ikm: fill(22, 0x0b), info: h('f0f1f2f3f4f5f6f7f8f9'), length: 42, want: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865' },
    // 44 bytes, as the key and nonce of a note
    { salt: text('sh20/v0/note/aead'), ikm: fill(32, 0x11), info: fill(32, 0x22), length: 44, want: 'ba078183b67a2a7fb6b11cf1516794a2bfc475ddb73ea673229e64f8afebb47e59ca08ba161a24246d3a57ff' },
  ],
  x25519: [
    // RFC 7748 §5.2
    { k: h('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'), u: h('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'), want: 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552' },
    { k: h('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'), u: h('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'), want: '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957' },
    // RFC 7748 §6.1: Alice's private key and Bob's public key
    { k: h('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'), u: h('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'), want: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742' },
  ],
  // RFC 7748 §6.1: the public key of Alice's private key
  x25519Public: { k: h('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'), want: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a' },
  // The seven encodings of the points of order 1, 2, 4 and 8: 0, 1, the two of order 8, p − 1, p, p + 1.
  lowOrder: [
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0100000000000000000000000000000000000000000000000000000000000000',
    'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
    '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  ].map(h),
  aesGcm: [
    // "The Galois/Counter Mode of Operation" (McGrew, Viega), test case 16
    {
      key: h('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'),
      nonce: h('cafebabefacedbaddecaf888'),
      aad: h('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
      plaintext: h('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
      want: '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b',
    },
    // the shape of a note: 12 bytes of plaintext, 32 bytes of associated data, 28 bytes out
    { key: fill(32, 0x33), nonce: fill(12, 0x44), aad: fill(32, 0x55), plaintext: h('e80300000000000047454e45'), want: 'd892c492ca068f6be7c7ead78ae83eaa52bdcd68822c4a52c0892990' },
  ],
});

/** Runs every known answer through `s`, the exports of subtle.js. Returns [{ name, ok, got, want }]. */
export async function knownAnswers(s) {
  const out = [];
  const check = async (name, want, fn) => {
    let got;
    try {
      got = await fn();
    } catch (e) {
      got = `threw ${e?.name}: ${e?.message}`;
    }
    out.push({ name, ok: got === want, got, want });
  };
  const flip = (b, i) => {
    const c = Uint8Array.from(b);
    c[i] ^= 1;
    return c;
  };

  await check('available', 'true', async () => String(await s.available()));
  await check('SHA-256', KAT.sha256.want, async () => hex(await s.sha256(KAT.sha256.data)));
  await check('SHA-256 of parts', KAT.sha256.want, async () => hex(await s.sha256(text('a'), text('b'), text('c'))));
  await check('HMAC-SHA512', KAT.hmacSha512.want, async () => hex(await s.hmacSha512(KAT.hmacSha512.key, KAT.hmacSha512.data)));
  for (const [i, k] of KAT.hkdf.entries()) await check(`HKDF-SHA256 #${i + 1} (${k.length} bytes)`, k.want, async () => hex(await s.hkdfSha256(k.salt, k.ikm, k.info, k.length)));
  for (const [i, k] of KAT.x25519.entries()) await check(`X25519 #${i + 1}`, k.want, async () => hex(await s.x25519(k.k, k.u)));
  await check('X25519 public key', KAT.x25519Public.want, async () => hex(await s.x25519Public(KAT.x25519Public.k)));
  for (const u of KAT.lowOrder) await check(`X25519 with the low-order point ${hex(u).slice(0, 8)}… is all zeros`, '00'.repeat(32), async () => hex(await s.x25519(KAT.x25519[0].k, u)));
  await check('X25519 refuses a 31-byte key', 'RangeError', async () => s.x25519(KAT.x25519[0].k.subarray(1), KAT.x25519[0].u).then(() => 'no error', (e) => e.name));
  for (const [i, k] of KAT.aesGcm.entries()) {
    const sealed = h(k.want);
    await check(`AES-256-GCM #${i + 1} seals`, k.want, async () => hex(await s.aes256GcmSeal(k.key, k.nonce, k.aad, k.plaintext)));
    await check(`AES-256-GCM #${i + 1} opens`, hex(k.plaintext), async () => hex(await s.aes256GcmOpen(k.key, k.nonce, k.aad, sealed)));
    await check(`AES-256-GCM #${i + 1} refuses another tag`, 'null', async () => String(await s.aes256GcmOpen(k.key, k.nonce, k.aad, flip(sealed, sealed.length - 1))));
    await check(`AES-256-GCM #${i + 1} refuses another ciphertext`, 'null', async () => String(await s.aes256GcmOpen(k.key, k.nonce, k.aad, flip(sealed, 0))));
    await check(`AES-256-GCM #${i + 1} refuses other associated data`, 'null', async () => String(await s.aes256GcmOpen(k.key, k.nonce, flip(k.aad, 0), sealed)));
    await check(`AES-256-GCM #${i + 1} refuses another key`, 'null', async () => String(await s.aes256GcmOpen(flip(k.key, 0), k.nonce, k.aad, sealed)));
  }
  return out;
}
