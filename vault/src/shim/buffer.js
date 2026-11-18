// Minimal Node `Buffer` for the browser: exactly the subset that
// indexer/src/{constants,codec,notes}.js use, so those files load unchanged.
// In Node the real Buffer is kept.

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

function check(v, max, name) {
  if (typeof v === 'bigint' ? v < 0n || v > max : !Number.isInteger(v) || v < 0 || v > max) {
    throw new RangeError(`${name}: value out of range`);
  }
}

class ShimBuffer extends Uint8Array {
  static from(x, enc) {
    if (typeof x === 'string') {
      if (enc === 'hex') {
        if (x.length % 2 || /[^0-9a-f]/i.test(x)) throw new TypeError('bad hex string');
        const b = new ShimBuffer(x.length / 2);
        for (let i = 0; i < b.length; i++) b[i] = parseInt(x.slice(2 * i, 2 * i + 2), 16);
        return b;
      }
      if (enc === 'latin1' || enc === 'ascii' || enc === 'binary') {
        const b = new ShimBuffer(x.length);
        for (let i = 0; i < x.length; i++) b[i] = x.charCodeAt(i) & 0xff;
        return b;
      }
      if (enc === undefined || enc === 'utf8' || enc === 'utf-8') return ShimBuffer.from(new TextEncoder().encode(x));
      throw new TypeError(`unsupported encoding ${enc}`);
    }
    if (x instanceof ArrayBuffer) return new ShimBuffer(x.slice(0));
    const b = new ShimBuffer(x.length);
    b.set(x);
    return b;
  }

  static alloc(n, fill = 0) {
    const b = new ShimBuffer(n);
    if (fill) b.fill(fill);
    return b;
  }

  static concat(list) {
    const out = new ShimBuffer(list.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of list) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }

  static isBuffer(b) {
    return b instanceof ShimBuffer;
  }

  get _dv() {
    return new DataView(this.buffer, this.byteOffset, this.byteLength);
  }

  equals(o) {
    if (this.length !== o.length) return false;
    for (let i = 0; i < this.length; i++) if (this[i] !== o[i]) return false;
    return true;
  }

  toString(enc = 'utf8') {
    if (enc === 'hex') {
      let s = '';
      for (const x of this) s += HEX[x];
      return s;
    }
    if (enc === 'latin1' || enc === 'binary') return String.fromCharCode(...this);
    if (enc === 'ascii') return String.fromCharCode(...this.map((x) => x & 0x7f));
    if (enc === 'utf8' || enc === 'utf-8') return new TextDecoder().decode(this);
    throw new TypeError(`unsupported encoding ${enc}`);
  }

  readUInt16LE(o = 0) {
    return this._dv.getUint16(o, true);
  }
  readUInt32LE(o = 0) {
    return this._dv.getUint32(o, true);
  }
  readUInt32BE(o = 0) {
    return this._dv.getUint32(o, false);
  }
  readBigUInt64LE(o = 0) {
    return this._dv.getBigUint64(o, true);
  }
  writeUInt16LE(v, o = 0) {
    check(v, 0xffff, 'writeUInt16LE');
    this._dv.setUint16(o, v, true);
    return o + 2;
  }
  writeUInt32LE(v, o = 0) {
    check(v, 0xffffffff, 'writeUInt32LE');
    this._dv.setUint32(o, v, true);
    return o + 4;
  }
  writeBigUInt64LE(v, o = 0) {
    if (typeof v !== 'bigint') throw new TypeError('writeBigUInt64LE needs a bigint');
    check(v, 0xffffffffffffffffn, 'writeBigUInt64LE');
    this._dv.setBigUint64(o, v, true);
    return o + 8;
  }
}

if (typeof globalThis.Buffer === 'undefined') globalThis.Buffer = ShimBuffer;

export { ShimBuffer };
export const Buffer = globalThis.Buffer;
