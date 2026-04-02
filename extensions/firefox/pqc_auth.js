var CyberArmorPQCAuthBundle = (() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
    get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
  }) : x)(function(x) {
    if (typeof require !== "undefined") return require.apply(this, arguments);
    throw Error('Dynamic require of "' + x + '" is not supported');
  });
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));

  // node_modules/mlkem/esm/src/errors.js
  var MlKemError = class extends Error {
    constructor(e) {
      let message;
      if (e instanceof Error) {
        message = e.message;
      } else if (typeof e === "string") {
        message = e;
      } else {
        message = "";
      }
      super(message);
      this.name = this.constructor.name;
    }
  };

  // node_modules/mlkem/esm/src/consts.js
  var N = 256;
  var Q = 3329;
  var Q_INV = 62209;
  var NTT_ZETAS = [
    2285,
    2571,
    2970,
    1812,
    1493,
    1422,
    287,
    202,
    3158,
    622,
    1577,
    182,
    962,
    2127,
    1855,
    1468,
    573,
    2004,
    264,
    383,
    2500,
    1458,
    1727,
    3199,
    2648,
    1017,
    732,
    608,
    1787,
    411,
    3124,
    1758,
    1223,
    652,
    2777,
    1015,
    2036,
    1491,
    3047,
    1785,
    516,
    3321,
    3009,
    2663,
    1711,
    2167,
    126,
    1469,
    2476,
    3239,
    3058,
    830,
    107,
    1908,
    3082,
    2378,
    2931,
    961,
    1821,
    2604,
    448,
    2264,
    677,
    2054,
    2226,
    430,
    555,
    843,
    2078,
    871,
    1550,
    105,
    422,
    587,
    177,
    3094,
    3038,
    2869,
    1574,
    1653,
    3083,
    778,
    1159,
    3182,
    2552,
    1483,
    2727,
    1119,
    1739,
    644,
    2457,
    349,
    418,
    329,
    3173,
    3254,
    817,
    1097,
    603,
    610,
    1322,
    2044,
    1864,
    384,
    2114,
    3193,
    1218,
    1994,
    2455,
    220,
    2142,
    1670,
    2144,
    1799,
    2051,
    794,
    1819,
    2475,
    2459,
    478,
    3221,
    3021,
    996,
    991,
    958,
    1869,
    1522,
    1628
  ];
  var NTT_ZETAS_INV = [
    1701,
    1807,
    1460,
    2371,
    2338,
    2333,
    308,
    108,
    2851,
    870,
    854,
    1510,
    2535,
    1278,
    1530,
    1185,
    1659,
    1187,
    3109,
    874,
    1335,
    2111,
    136,
    1215,
    2945,
    1465,
    1285,
    2007,
    2719,
    2726,
    2232,
    2512,
    75,
    156,
    3e3,
    2911,
    2980,
    872,
    2685,
    1590,
    2210,
    602,
    1846,
    777,
    147,
    2170,
    2551,
    246,
    1676,
    1755,
    460,
    291,
    235,
    3152,
    2742,
    2907,
    3224,
    1779,
    2458,
    1251,
    2486,
    2774,
    2899,
    1103,
    1275,
    2652,
    1065,
    2881,
    725,
    1508,
    2368,
    398,
    951,
    247,
    1421,
    3222,
    2499,
    271,
    90,
    853,
    1860,
    3203,
    1162,
    1618,
    666,
    320,
    8,
    2813,
    1544,
    282,
    1838,
    1293,
    2314,
    552,
    2677,
    2106,
    1571,
    205,
    2918,
    1542,
    2721,
    2597,
    2312,
    681,
    130,
    1602,
    1871,
    829,
    2946,
    3065,
    1325,
    2756,
    1861,
    1474,
    1202,
    2367,
    3147,
    1752,
    2707,
    171,
    3127,
    3042,
    1907,
    1836,
    1517,
    359,
    758,
    1441
  ];

  // node_modules/mlkem/esm/src/sha3/_u64.js
  var U32_MASK64 = 0xffffffffn;
  var _32n = 32n;
  function fromBig(n, le = false) {
    if (le) {
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    }
    return {
      h: Number(n >> _32n & U32_MASK64) | 0,
      l: Number(n & U32_MASK64) | 0
    };
  }
  function split(lst, le = false) {
    const len = lst.length;
    const Ah = new Uint32Array(len);
    const Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  }
  var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
  var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
  var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
  var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;

  // node_modules/mlkem/esm/src/sha3/utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
  }
  function anumber(n, title = "") {
    if (!Number.isSafeInteger(n) || n < 0) {
      const prefix = title && `"${title}" `;
      throw new Error(`${prefix}expected integer >0, got ${n}`);
    }
  }
  function abytes(value, length, title = "") {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== void 0;
    if (!bytes || needsLen && len !== length) {
      const prefix = title && `"${title}" `;
      const ofLen = needsLen ? ` of length ${length}` : "";
      const got = bytes ? `length=${len}` : `type=${typeof value}`;
      throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
    }
    return value;
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished) {
      throw new Error("Hash#digest() has already been called");
    }
  }
  function aoutput(out, instance) {
    abytes(out, void 0, "digestInto() output");
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error('"digestInto() output" expected to be of length >=' + min);
    }
  }
  function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
  function byteSwap(word) {
    return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  }
  function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = byteSwap(arr[i]);
    }
    return arr;
  }
  var swap32IfBE = isLE ? (u) => u : byteSwap32;

  // node_modules/mlkem/esm/src/sha3/sha3.js
  var _0n = 0n;
  var _1n = 1n;
  var _2n = 2n;
  var _7n = 7n;
  var _256n = 256n;
  var _0x71n = 0x71n;
  var SHA3_PI = [];
  var SHA3_ROTL = [];
  var _SHA3_IOTA = [];
  for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
    let t = _0n;
    for (let j = 0; j < 7; j++) {
      R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
      if (R & _2n)
        t ^= _1n << (_1n << BigInt(j)) - _1n;
    }
    _SHA3_IOTA.push(t);
  }
  var IOTAS = split(_SHA3_IOTA, true);
  var SHA3_IOTA_H = IOTAS[0];
  var SHA3_IOTA_L = IOTAS[1];
  var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
  var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
  function keccakP(s, rounds = 24, B) {
    if (!B)
      B = new Uint32Array(10);
    for (let round = 24 - rounds; round < 24; round++) {
      for (let x = 0; x < 10; x++) {
        B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
      }
      {
        const Th2 = rotlH(B[2], B[3], 1) ^ B[8];
        const Tl2 = rotlL(B[2], B[3], 1) ^ B[9];
        s[0] ^= Th2;
        s[1] ^= Tl2;
        s[10] ^= Th2;
        s[11] ^= Tl2;
        s[20] ^= Th2;
        s[21] ^= Tl2;
        s[30] ^= Th2;
        s[31] ^= Tl2;
        s[40] ^= Th2;
        s[41] ^= Tl2;
      }
      {
        const Th2 = rotlH(B[4], B[5], 1) ^ B[0];
        const Tl2 = rotlL(B[4], B[5], 1) ^ B[1];
        s[2] ^= Th2;
        s[3] ^= Tl2;
        s[12] ^= Th2;
        s[13] ^= Tl2;
        s[22] ^= Th2;
        s[23] ^= Tl2;
        s[32] ^= Th2;
        s[33] ^= Tl2;
        s[42] ^= Th2;
        s[43] ^= Tl2;
      }
      {
        const Th2 = rotlH(B[6], B[7], 1) ^ B[2];
        const Tl2 = rotlL(B[6], B[7], 1) ^ B[3];
        s[4] ^= Th2;
        s[5] ^= Tl2;
        s[14] ^= Th2;
        s[15] ^= Tl2;
        s[24] ^= Th2;
        s[25] ^= Tl2;
        s[34] ^= Th2;
        s[35] ^= Tl2;
        s[44] ^= Th2;
        s[45] ^= Tl2;
      }
      {
        const Th2 = rotlH(B[8], B[9], 1) ^ B[4];
        const Tl2 = rotlL(B[8], B[9], 1) ^ B[5];
        s[6] ^= Th2;
        s[7] ^= Tl2;
        s[16] ^= Th2;
        s[17] ^= Tl2;
        s[26] ^= Th2;
        s[27] ^= Tl2;
        s[36] ^= Th2;
        s[37] ^= Tl2;
        s[46] ^= Th2;
        s[47] ^= Tl2;
      }
      {
        const Th2 = rotlH(B[0], B[1], 1) ^ B[6];
        const Tl2 = rotlL(B[0], B[1], 1) ^ B[7];
        s[8] ^= Th2;
        s[9] ^= Tl2;
        s[18] ^= Th2;
        s[19] ^= Tl2;
        s[28] ^= Th2;
        s[29] ^= Tl2;
        s[38] ^= Th2;
        s[39] ^= Tl2;
        s[48] ^= Th2;
        s[49] ^= Tl2;
      }
      let curH = s[2];
      let curL = s[3];
      let Th, Tl;
      Th = rotlSH(curH, curL, 1);
      Tl = rotlSL(curH, curL, 1);
      curH = s[20];
      curL = s[21];
      s[20] = Th;
      s[21] = Tl;
      Th = rotlSH(curH, curL, 3);
      Tl = rotlSL(curH, curL, 3);
      curH = s[14];
      curL = s[15];
      s[14] = Th;
      s[15] = Tl;
      Th = rotlSH(curH, curL, 6);
      Tl = rotlSL(curH, curL, 6);
      curH = s[22];
      curL = s[23];
      s[22] = Th;
      s[23] = Tl;
      Th = rotlSH(curH, curL, 10);
      Tl = rotlSL(curH, curL, 10);
      curH = s[34];
      curL = s[35];
      s[34] = Th;
      s[35] = Tl;
      Th = rotlSH(curH, curL, 15);
      Tl = rotlSL(curH, curL, 15);
      curH = s[36];
      curL = s[37];
      s[36] = Th;
      s[37] = Tl;
      Th = rotlSH(curH, curL, 21);
      Tl = rotlSL(curH, curL, 21);
      curH = s[6];
      curL = s[7];
      s[6] = Th;
      s[7] = Tl;
      Th = rotlSH(curH, curL, 28);
      Tl = rotlSL(curH, curL, 28);
      curH = s[10];
      curL = s[11];
      s[10] = Th;
      s[11] = Tl;
      Th = rotlBH(curH, curL, 36);
      Tl = rotlBL(curH, curL, 36);
      curH = s[32];
      curL = s[33];
      s[32] = Th;
      s[33] = Tl;
      Th = rotlBH(curH, curL, 45);
      Tl = rotlBL(curH, curL, 45);
      curH = s[16];
      curL = s[17];
      s[16] = Th;
      s[17] = Tl;
      Th = rotlBH(curH, curL, 55);
      Tl = rotlBL(curH, curL, 55);
      curH = s[42];
      curL = s[43];
      s[42] = Th;
      s[43] = Tl;
      Th = rotlSH(curH, curL, 2);
      Tl = rotlSL(curH, curL, 2);
      curH = s[48];
      curL = s[49];
      s[48] = Th;
      s[49] = Tl;
      Th = rotlSH(curH, curL, 14);
      Tl = rotlSL(curH, curL, 14);
      curH = s[8];
      curL = s[9];
      s[8] = Th;
      s[9] = Tl;
      Th = rotlSH(curH, curL, 27);
      Tl = rotlSL(curH, curL, 27);
      curH = s[30];
      curL = s[31];
      s[30] = Th;
      s[31] = Tl;
      Th = rotlBH(curH, curL, 41);
      Tl = rotlBL(curH, curL, 41);
      curH = s[46];
      curL = s[47];
      s[46] = Th;
      s[47] = Tl;
      Th = rotlBH(curH, curL, 56);
      Tl = rotlBL(curH, curL, 56);
      curH = s[38];
      curL = s[39];
      s[38] = Th;
      s[39] = Tl;
      Th = rotlSH(curH, curL, 8);
      Tl = rotlSL(curH, curL, 8);
      curH = s[26];
      curL = s[27];
      s[26] = Th;
      s[27] = Tl;
      Th = rotlSH(curH, curL, 25);
      Tl = rotlSL(curH, curL, 25);
      curH = s[24];
      curL = s[25];
      s[24] = Th;
      s[25] = Tl;
      Th = rotlBH(curH, curL, 43);
      Tl = rotlBL(curH, curL, 43);
      curH = s[4];
      curL = s[5];
      s[4] = Th;
      s[5] = Tl;
      Th = rotlBH(curH, curL, 62);
      Tl = rotlBL(curH, curL, 62);
      curH = s[40];
      curL = s[41];
      s[40] = Th;
      s[41] = Tl;
      Th = rotlSH(curH, curL, 18);
      Tl = rotlSL(curH, curL, 18);
      curH = s[28];
      curL = s[29];
      s[28] = Th;
      s[29] = Tl;
      Th = rotlBH(curH, curL, 39);
      Tl = rotlBL(curH, curL, 39);
      curH = s[44];
      curL = s[45];
      s[44] = Th;
      s[45] = Tl;
      Th = rotlBH(curH, curL, 61);
      Tl = rotlBL(curH, curL, 61);
      curH = s[18];
      curL = s[19];
      s[18] = Th;
      s[19] = Tl;
      Th = rotlSH(curH, curL, 20);
      Tl = rotlSL(curH, curL, 20);
      curH = s[12];
      curL = s[13];
      s[12] = Th;
      s[13] = Tl;
      Th = rotlBH(curH, curL, 44);
      Tl = rotlBL(curH, curL, 44);
      s[2] = Th;
      s[3] = Tl;
      for (let y = 0; y < 50; y += 10) {
        B[0] = s[y];
        B[1] = s[y + 1];
        B[2] = s[y + 2];
        B[3] = s[y + 3];
        B[4] = s[y + 4];
        B[5] = s[y + 5];
        B[6] = s[y + 6];
        B[7] = s[y + 7];
        B[8] = s[y + 8];
        B[9] = s[y + 9];
        s[y + 0] ^= ~B[2] & B[4];
        s[y + 1] ^= ~B[3] & B[5];
        s[y + 2] ^= ~B[4] & B[6];
        s[y + 3] ^= ~B[5] & B[7];
        s[y + 4] ^= ~B[6] & B[8];
        s[y + 5] ^= ~B[7] & B[9];
        s[y + 6] ^= ~B[8] & B[0];
        s[y + 7] ^= ~B[9] & B[1];
        s[y + 8] ^= ~B[0] & B[2];
        s[y + 9] ^= ~B[1] & B[3];
      }
      s[0] ^= SHA3_IOTA_H[round];
      s[1] ^= SHA3_IOTA_L[round];
    }
  }
  var Keccak = class _Keccak {
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
      Object.defineProperty(this, "state", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "pos", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "posOut", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "finished", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: false
      });
      Object.defineProperty(this, "state32", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "destroyed", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: false
      });
      Object.defineProperty(this, "_B", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint32Array(10)
      });
      Object.defineProperty(this, "blockLen", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "suffix", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "outputLen", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "enableXOF", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: false
      });
      Object.defineProperty(this, "rounds", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      this.blockLen = blockLen;
      this.suffix = suffix;
      this.outputLen = outputLen;
      this.enableXOF = enableXOF;
      this.rounds = rounds;
      anumber(outputLen, "outputLen");
      if (!(0 < blockLen && blockLen < 200)) {
        throw new Error("only keccak-f1600 function is supported");
      }
      this.state = new Uint8Array(200);
      this.state32 = u32(this.state);
    }
    clone() {
      return this._cloneInto();
    }
    /** Resets instance to initial (empty) state for reuse. */
    reset() {
      this.state.fill(0);
      this.pos = 0;
      this.posOut = 0;
      this.finished = false;
      this.destroyed = false;
    }
    keccak() {
      swap32IfBE(this.state32);
      keccakP(this.state32, this.rounds, this._B);
      swap32IfBE(this.state32);
      this.posOut = 0;
      this.pos = 0;
    }
    update(data) {
      aexists(this);
      abytes(data);
      return this.updateUnsafe(data);
    }
    /** Like update(), but skips validation. Caller must ensure valid state and input. */
    updateUnsafe(data) {
      const { blockLen, state } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        for (let i = 0; i < take; i++)
          state[this.pos++] ^= data[pos++];
        if (this.pos === blockLen)
          this.keccak();
      }
      return this;
    }
    finish() {
      if (this.finished)
        return;
      this.finished = true;
      const { state, suffix, pos, blockLen } = this;
      state[pos] ^= suffix;
      if ((suffix & 128) !== 0 && pos === blockLen - 1)
        this.keccak();
      state[blockLen - 1] ^= 128;
      this.keccak();
    }
    writeInto(out) {
      aexists(this, false);
      abytes(out);
      return this.writeIntoUnsafe(out);
    }
    /** Like writeInto(), but skips validation. Caller must ensure valid state and output. */
    writeIntoUnsafe(out) {
      this.finish();
      const bufferOut = this.state;
      const { blockLen } = this;
      for (let pos = 0, len = out.length; pos < len; ) {
        if (this.posOut >= blockLen)
          this.keccak();
        const take = Math.min(blockLen - this.posOut, len - pos);
        out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
        this.posOut += take;
        pos += take;
      }
      return out;
    }
    xofInto(out) {
      if (!this.enableXOF) {
        throw new Error("XOF is not possible for this instance");
      }
      return this.writeInto(out);
    }
    xof(bytes) {
      anumber(bytes);
      return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
      aoutput(out, this);
      if (this.finished)
        throw new Error("digest() was already called");
      this.writeInto(out);
      this.destroy();
      return out;
    }
    digest() {
      return this.digestInto(new Uint8Array(this.outputLen));
    }
    destroy() {
      this.destroyed = true;
      clean(this.state);
    }
    _cloneInto(to) {
      const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
      to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
      to.state32.set(this.state32);
      to.pos = this.pos;
      to.posOut = this.posOut;
      to.finished = this.finished;
      to.rounds = rounds;
      to.suffix = suffix;
      to.outputLen = outputLen;
      to.enableXOF = enableXOF;
      to.destroyed = this.destroyed;
      return to;
    }
  };

  // node_modules/mlkem/esm/_dnt.shims.js
  var dntGlobals = {};
  var dntGlobalThis = createMergeProxy(globalThis, dntGlobals);
  function createMergeProxy(baseObj, extObj) {
    return new Proxy(baseObj, {
      get(_target, prop, _receiver) {
        if (prop in extObj) {
          return extObj[prop];
        } else {
          return baseObj[prop];
        }
      },
      set(_target, prop, value) {
        if (prop in extObj) {
          delete extObj[prop];
        }
        baseObj[prop] = value;
        return true;
      },
      deleteProperty(_target, prop) {
        let success = false;
        if (prop in extObj) {
          delete extObj[prop];
          success = true;
        }
        if (prop in baseObj) {
          delete baseObj[prop];
          success = true;
        }
        return success;
      },
      ownKeys(_target) {
        const baseKeys = Reflect.ownKeys(baseObj);
        const extKeys = Reflect.ownKeys(extObj);
        const extKeysSet = new Set(extKeys);
        return [...baseKeys.filter((k) => !extKeysSet.has(k)), ...extKeys];
      },
      defineProperty(_target, prop, desc) {
        if (prop in extObj) {
          delete extObj[prop];
        }
        Reflect.defineProperty(baseObj, prop, desc);
        return true;
      },
      getOwnPropertyDescriptor(_target, prop) {
        if (prop in extObj) {
          return Reflect.getOwnPropertyDescriptor(extObj, prop);
        } else {
          return Reflect.getOwnPropertyDescriptor(baseObj, prop);
        }
      },
      has(_target, prop) {
        return prop in extObj || prop in baseObj;
      }
    });
  }

  // node_modules/mlkem/esm/src/utils.js
  function byte(n) {
    return n & 255;
  }
  function int16(n) {
    return n << 16 >> 16;
  }
  function uint16(n) {
    return n & 65535;
  }
  function uint32(n) {
    return n >>> 0;
  }
  function constantTimeCompare(x, y) {
    if (x.length != y.length) {
      return 0;
    }
    let v = 0;
    for (let i = 0; i < x.length; i++) {
      v |= x[i] ^ y[i];
    }
    let z = ~v & 255;
    z &= z >> 4;
    z &= z >> 2;
    z &= z >> 1;
    return z & 1;
  }
  function equalUint8Array(x, y) {
    if (x.length != y.length) {
      return false;
    }
    for (let i = 0; i < x.length; i++) {
      if (x[i] !== y[i]) {
        return false;
      }
    }
    return true;
  }
  async function loadCrypto() {
    if (typeof dntGlobalThis !== "undefined" && globalThis.crypto !== void 0) {
      return globalThis.crypto;
    }
    try {
      const { webcrypto } = await import("crypto");
      return webcrypto;
    } catch (_e) {
      throw new Error("failed to load Crypto");
    }
  }
  function byteopsLoad32(x, o = 0) {
    return (x[o] | x[o + 1] << 8 | x[o + 2] << 16 | x[o + 3] << 24) >>> 0;
  }

  // node_modules/mlkem/esm/src/mlKemBase.js
  var MlKemBase = class {
    /**
     * Creates a new instance of the MlKemBase class.
     */
    constructor() {
      Object.defineProperty(this, "_api", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_k", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_du", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_dv", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_eta1", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_eta2", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_skSize", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_pkSize", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_compressedUSize", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_compressedVSize", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_poolG", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolH", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolKdf", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolXof", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolPrf1", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolPrf2", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_bufG", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(64)
      });
      Object.defineProperty(this, "_bufH", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(32)
      });
      Object.defineProperty(this, "_bufKdf", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(32)
      });
      Object.defineProperty(this, "_bufXof", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(672)
      });
      Object.defineProperty(this, "_bufPrf1", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_bufPrf2", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_nonceBuf", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(1)
      });
      Object.defineProperty(this, "_xofSeed", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(34)
      });
      Object.defineProperty(this, "_kBuf", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_matrixA", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_noiseVecs", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_polyVec", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_bufPkCheck", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_bufCt", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
    }
    _initPool() {
      this._poolG = new Keccak(72, 6, 64);
      this._poolH = new Keccak(136, 6, 32);
      this._poolKdf = new Keccak(136, 31, 32, true);
      this._poolXof = new Keccak(168, 31, 672, true);
      const prf1Len = this._eta1 * N / 4;
      this._poolPrf1 = new Keccak(136, 31, prf1Len, true);
      this._bufPrf1 = new Uint8Array(prf1Len);
      const prf2Len = this._eta2 * N / 4;
      this._poolPrf2 = new Keccak(136, 31, prf2Len, true);
      this._bufPrf2 = new Uint8Array(prf2Len);
      this._kBuf = new Uint8Array([this._k]);
      this._matrixA = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        this._matrixA[i] = new Array(this._k);
        for (let j = 0; j < this._k; j++) {
          this._matrixA[i][j] = new Int16Array(N);
        }
      }
      const maxNoise = 2 * this._k + 1;
      this._noiseVecs = new Array(maxNoise);
      for (let i = 0; i < maxNoise; i++) {
        this._noiseVecs[i] = new Int16Array(N);
      }
      this._polyVec = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        this._polyVec[i] = new Int16Array(N);
      }
      this._bufPkCheck = new Uint8Array(384 * this._k);
      this._bufCt = new Uint8Array(this._compressedUSize + this._compressedVSize);
    }
    _zeroPool() {
      this._bufG.fill(0);
      this._bufH.fill(0);
      this._bufKdf.fill(0);
      this._bufXof.fill(0);
      this._bufPrf1.fill(0);
      this._bufPrf2.fill(0);
      this._nonceBuf[0] = 0;
      this._xofSeed.fill(0);
      for (let i = 0; i < this._k; i++) {
        for (let j = 0; j < this._k; j++) {
          this._matrixA[i][j].fill(0);
        }
      }
      for (let i = 0; i < this._noiseVecs.length; i++) {
        this._noiseVecs[i].fill(0);
      }
      for (let i = 0; i < this._k; i++) {
        this._polyVec[i].fill(0);
      }
      this._bufPkCheck.fill(0);
      this._bufCt.fill(0);
      this._poolG.reset();
      this._poolH.reset();
      this._poolKdf.reset();
      this._poolXof.reset();
      this._poolPrf1.reset();
      this._poolPrf2.reset();
    }
    // Serialize polynomial into byte buffer at offset (eliminates intermediate Uint8Array(384))
    _polyToBytes(out, outOffset, a) {
      let t0, t1;
      for (let i = 0; i < N / 2; i++) {
        t0 = a[2 * i] - Q;
        t0 += t0 >> 31 & Q;
        t1 = a[2 * i + 1] - Q;
        t1 += t1 >> 31 & Q;
        out[outOffset + 3 * i + 0] = byte(t0);
        out[outOffset + 3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4);
        out[outOffset + 3 * i + 2] = byte(t1 >> 4);
      }
    }
    // Deserialize bytes into polynomial (eliminates intermediate Int16Array(N))
    _polyFromBytes(out, a, aOffset) {
      for (let i = 0; i < N / 2; i++) {
        out[2 * i] = int16((uint16(a[aOffset + 3 * i + 0]) >> 0 | uint16(a[aOffset + 3 * i + 1]) << 8) & 4095);
        out[2 * i + 1] = int16((uint16(a[aOffset + 3 * i + 1]) >> 4 | uint16(a[aOffset + 3 * i + 2]) << 4) & 4095);
      }
    }
    // Hash G: SHA3-512
    _g(a, b) {
      this._poolG.reset();
      this._poolG.updateUnsafe(a);
      if (b !== void 0)
        this._poolG.updateUnsafe(b);
      this._poolG.writeIntoUnsafe(this._bufG);
      return [this._bufG.subarray(0, 32), this._bufG.subarray(32, 64)];
    }
    // Hash H: SHA3-256
    _h(msg) {
      this._poolH.reset();
      this._poolH.updateUnsafe(msg).writeIntoUnsafe(this._bufH);
      return this._bufH;
    }
    // KDF: SHAKE256(dkLen=32)
    _kdf(a, b) {
      this._poolKdf.reset();
      this._poolKdf.updateUnsafe(a);
      if (b !== void 0)
        this._poolKdf.updateUnsafe(b);
      this._poolKdf.writeIntoUnsafe(this._bufKdf);
      return this._bufKdf;
    }
    // XOF: SHAKE128(dkLen=672)
    _xof(seed) {
      this._poolXof.reset();
      this._poolXof.updateUnsafe(seed).writeIntoUnsafe(this._bufXof);
      return this._bufXof;
    }
    // PRF for eta1 noise sampling: SHAKE256(dkLen=eta1*N/4)
    _prf1(sigma, nonce) {
      this._nonceBuf[0] = nonce;
      this._poolPrf1.reset();
      this._poolPrf1.updateUnsafe(sigma).updateUnsafe(this._nonceBuf).writeIntoUnsafe(this._bufPrf1);
      return this._bufPrf1;
    }
    // PRF for eta2 noise sampling: SHAKE256(dkLen=eta2*N/4)
    _prf2(sigma, nonce) {
      this._nonceBuf[0] = nonce;
      this._poolPrf2.reset();
      this._poolPrf2.updateUnsafe(sigma).updateUnsafe(this._nonceBuf).writeIntoUnsafe(this._bufPrf2);
      return this._bufPrf2;
    }
    _generateKeyPairCore() {
      try {
        const rnd = new Uint8Array(64);
        this._api.getRandomValues(rnd);
        return this._deriveKeyPair(rnd);
      } finally {
        this._zeroPool();
      }
    }
    _deriveKeyPairCore(seed) {
      try {
        if (seed.byteLength !== 64) {
          throw new Error("seed must be 64 bytes in length");
        }
        return this._deriveKeyPair(seed);
      } finally {
        this._zeroPool();
      }
    }
    _encapCore(pk, seed) {
      try {
        if (pk.length !== 384 * this._k + 32) {
          throw new Error("invalid encapsulation key");
        }
        const m = this._getSeed(seed);
        const [k, r] = this._g(m, this._h(pk));
        this._encap(pk, m, r);
        return [this._bufCt.slice(), k.slice()];
      } finally {
        this._zeroPool();
      }
    }
    _decapCore(ct, sk) {
      try {
        if (ct.byteLength !== this._compressedUSize + this._compressedVSize) {
          throw new Error("Invalid ct size");
        }
        if (sk.length !== 768 * this._k + 96) {
          throw new Error("Invalid decapsulation key");
        }
        const sk2 = sk.subarray(0, this._skSize);
        const pk = sk.subarray(this._skSize, this._skSize + this._pkSize);
        const hpk = sk.subarray(this._skSize + this._pkSize, this._skSize + this._pkSize + 32);
        const z = sk.subarray(this._skSize + this._pkSize + 32, this._skSize + this._pkSize + 64);
        const m2 = this._decap(ct, sk2);
        const [k2, r2] = this._g(m2, hpk);
        const kBar = this._kdf(z, ct);
        this._encap(pk, m2, r2);
        return constantTimeCompare(ct, this._bufCt) === 1 ? k2.slice() : kBar.slice();
      } finally {
        this._zeroPool();
      }
    }
    /**
     * Sets up the MlKemBase instance by loading the necessary crypto library.
     * If the crypto library is already loaded, this method does nothing.
     * @returns {Promise<void>} A promise that resolves when the setup is complete.
     */
    async _setup() {
      if (this._api !== void 0) {
        return;
      }
      this._api = await loadCrypto();
    }
    /**
     * Returns a Uint8Array seed for cryptographic operations.
     * If no seed is provided, a random seed of length 32 bytes is generated.
     * If a seed is provided, it must be exactly 32 bytes in length.
     *
     * @param seed - Optional seed for cryptographic operations.
     * @returns A Uint8Array seed.
     * @throws Error if the provided seed is not 32 bytes in length.
     */
    _getSeed(seed) {
      if (seed == void 0) {
        const s = new Uint8Array(32);
        this._api.getRandomValues(s);
        return s;
      }
      if (seed.byteLength !== 32) {
        throw new Error("seed must be 32 bytes in length");
      }
      return seed;
    }
    /**
     * Derives a key pair from a given seed.
     *
     * @param seed - The seed used for key derivation.
     * @returns An array containing the public key and secret key.
     */
    _deriveKeyPair(seed) {
      const cpaSeed = seed.subarray(0, 32);
      const z = seed.subarray(32, 64);
      const [pk, skBody] = this._deriveCpaKeyPair(cpaSeed);
      const pkh = this._h(pk);
      const sk = new Uint8Array(this._skSize + this._pkSize + 64);
      sk.set(skBody, 0);
      sk.set(pk, this._skSize);
      sk.set(pkh, this._skSize + this._pkSize);
      sk.set(z, this._skSize + this._pkSize + 32);
      return [pk, sk];
    }
    // indcpaKeyGen generates public and private keys for the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Derives a CPA key pair using the provided CPA seed.
     *
     * @param cpaSeed - The CPA seed used for key derivation.
     * @returns An array containing the public key and private key.
     */
    _deriveCpaKeyPair(cpaSeed) {
      const [publicSeed, noiseSeed] = this._g(cpaSeed, this._kBuf);
      const a = this._sampleMatrix(publicSeed, false);
      const s = this._sampleNoise1(noiseSeed, 0, this._k);
      const e = this._sampleNoise1(noiseSeed, this._k, this._k);
      for (let i = 0; i < this._k; i++) {
        s[i] = ntt(s[i]);
        s[i] = reduce(s[i]);
        e[i] = ntt(e[i]);
      }
      const pk = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        pk[i] = polyToMont(multiply(a[i], s));
        pk[i] = add(pk[i], e[i]);
        pk[i] = reduce(pk[i]);
      }
      const pubKey = new Uint8Array(this._pkSize);
      for (let i = 0; i < this._k; i++) {
        this._polyToBytes(pubKey, i * 384, pk[i]);
      }
      pubKey.set(publicSeed, this._skSize);
      const privKey = new Uint8Array(this._skSize);
      for (let i = 0; i < this._k; i++) {
        this._polyToBytes(privKey, i * 384, s[i]);
      }
      return [pubKey, privKey];
    }
    // _encap is the encapsulation function of the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Encapsulates a message using the ML-KEM encryption scheme.
     *
     * @param pk - The public key.
     * @param msg - The message to be encapsulated.
     * @param seed - The seed used for generating random values.
     * @returns The encapsulated message as a Uint8Array.
     */
    _encap(pk, msg, seed) {
      const tHat = this._polyVec;
      const pkCheck = this._bufPkCheck;
      for (let i = 0; i < this._k; i++) {
        this._polyFromBytes(tHat[i], pk, i * 384);
        this._polyToBytes(pkCheck, i * 384, tHat[i]);
      }
      if (!equalUint8Array(pk.subarray(0, pkCheck.length), pkCheck)) {
        throw new Error("invalid encapsulation key");
      }
      const rho = pk.subarray(this._skSize);
      const a = this._sampleMatrix(rho, true);
      const r = this._sampleNoise1(seed, 0, this._k);
      const e1 = this._sampleNoise2(seed, this._k, this._k);
      const e2 = this._sampleNoise2(seed, this._k * 2, 1)[0];
      for (let i = 0; i < this._k; i++) {
        r[i] = ntt(r[i]);
        r[i] = reduce(r[i]);
      }
      const u = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        u[i] = multiply(a[i], r);
        u[i] = nttInverse(u[i]);
        u[i] = add(u[i], e1[i]);
        u[i] = reduce(u[i]);
      }
      const m = polyFromMsg(msg);
      let v = multiply(tHat, r);
      v = nttInverse(v);
      v = add(v, e2);
      v = add(v, m);
      v = reduce(v);
      this._compressU(this._bufCt.subarray(0, this._compressedUSize), u);
      this._compressV(this._bufCt.subarray(this._compressedUSize), v);
      return this._bufCt;
    }
    // indcpaDecrypt is the decryption function of the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Decapsulates the ciphertext using the provided secret key.
     *
     * @param ct - The ciphertext to be decapsulated.
     * @param sk - The secret key used for decapsulation.
     * @returns The decapsulated message as a Uint8Array.
     */
    _decap(ct, sk) {
      const u = this._decompressU(ct.subarray(0, this._compressedUSize));
      const v = this._decompressV(ct.subarray(this._compressedUSize));
      const privateKeyPolyvec = this._polyvecFromBytes(sk);
      for (let i = 0; i < this._k; i++) {
        u[i] = ntt(u[i]);
      }
      let mp = multiply(privateKeyPolyvec, u);
      mp = nttInverse(mp);
      mp = subtract(v, mp);
      mp = reduce(mp);
      return polyToMsg(mp);
    }
    // generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
    // from a seed. Entries of the matrix are polynomials that look uniformly random.
    // Performs rejection sampling on the output of an extendable-output function (XOF).
    /**
     * Generates a sample matrix based on the provided seed and transposition flag.
     *
     * @param seed - The seed used for generating the matrix.
     * @param transposed - A flag indicating whether the matrix should be transposed or not.
     * @returns The generated sample matrix.
     */
    _sampleMatrix(seed, transposed) {
      const a = this._matrixA;
      this._xofSeed.set(seed);
      for (let ctr = 0, i = 0; i < this._k; i++) {
        for (let j = 0; j < this._k; j++) {
          if (transposed) {
            this._xofSeed[seed.length] = i;
            this._xofSeed[seed.length + 1] = j;
          } else {
            this._xofSeed[seed.length] = j;
            this._xofSeed[seed.length + 1] = i;
          }
          const output = this._xof(this._xofSeed);
          ctr = indcpaRejUniform(a[i][j], 0, output.subarray(0, 504), 504, N);
          while (ctr < N) {
            const outputn = output.subarray(504, 672);
            ctr += indcpaRejUniform(a[i][j], ctr, outputn, 168, N - ctr);
          }
        }
      }
      return a;
    }
    /**
     * Generates a 2D array of noise samples.
     *
     * @param sigma - The noise parameter.
     * @param offset - The offset value.
     * @param size - The size of the array.
     * @returns The generated 2D array of noise samples.
     */
    _sampleNoise1(sigma, offset, size) {
      const r = new Array(size);
      for (let i = 0; i < size; i++) {
        r[i] = this._noiseVecs[offset + i];
        byteopsCbd(r[i], this._prf1(sigma, offset + i), this._eta1);
      }
      return r;
    }
    /**
     * Generates a 2-dimensional array of noise samples.
     *
     * @param sigma - The noise parameter.
     * @param offset - The offset value.
     * @param size - The size of the array.
     * @returns The generated 2-dimensional array of noise samples.
     */
    _sampleNoise2(sigma, offset, size) {
      const r = new Array(size);
      for (let i = 0; i < size; i++) {
        r[i] = this._noiseVecs[offset + i];
        byteopsCbd(r[i], this._prf2(sigma, offset + i), this._eta2);
      }
      return r;
    }
    // polyvecFromBytes deserializes a vector of polynomials.
    /**
     * Converts a Uint8Array to a 2D array of numbers representing a polynomial vector.
     * Each element in the resulting array represents a polynomial.
     * @param a The Uint8Array to convert.
     * @returns The 2D array of numbers representing the polynomial vector.
     */
    _polyvecFromBytes(a) {
      const r = this._polyVec;
      for (let i = 0; i < this._k; i++) {
        this._polyFromBytes(r[i], a, i * 384);
      }
      return r;
    }
    // compressU lossily compresses and serializes a vector of polynomials.
    /**
     * Compresses the given array of coefficients into a Uint8Array.
     *
     * @param r - The output Uint8Array.
     * @param u - The array of coefficients.
     * @returns The compressed Uint8Array.
     */
    _compressU(r, u) {
      const t = new Array(4);
      for (let rr = 0, i = 0; i < this._k; i++) {
        for (let j = 0; j < N / 4; j++) {
          for (let k = 0; k < 4; k++) {
            t[k] = ((u[i][4 * j + k] << 10) + Q / 2) / Q & 1023;
          }
          r[rr++] = byte(t[0] >> 0);
          r[rr++] = byte(t[0] >> 8 | t[1] << 2);
          r[rr++] = byte(t[1] >> 6 | t[2] << 4);
          r[rr++] = byte(t[2] >> 4 | t[3] << 6);
          r[rr++] = byte(t[3] >> 2);
        }
      }
      return r;
    }
    // compressV lossily compresses and subsequently serializes a polynomial.
    /**
     * Compresses the given array of numbers into a Uint8Array.
     *
     * @param r - The Uint8Array to store the compressed values.
     * @param v - The array of numbers to compress.
     * @returns The compressed Uint8Array.
     */
    _compressV(r, v) {
      const t = new Uint8Array(8);
      for (let rr = 0, i = 0; i < N / 8; i++) {
        for (let j = 0; j < 8; j++) {
          t[j] = byte(((v[8 * i + j] << 4) + Q / 2) / Q) & 15;
        }
        r[rr++] = t[0] | t[1] << 4;
        r[rr++] = t[2] | t[3] << 4;
        r[rr++] = t[4] | t[5] << 4;
        r[rr++] = t[6] | t[7] << 4;
      }
      return r;
    }
    // decompressU de-serializes and decompresses a vector of polynomials and
    // represents the approximate inverse of compress1. Since compression is lossy,
    // the results of decompression will may not match the original vector of polynomials.
    /**
     * Decompresses a Uint8Array into a two-dimensional array of numbers.
     *
     * @param a The Uint8Array to decompress.
     * @returns The decompressed two-dimensional array.
     */
    _decompressU(a) {
      const r = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        r[i] = new Int16Array(N);
      }
      const t = new Array(4);
      for (let aa = 0, i = 0; i < this._k; i++) {
        for (let j = 0; j < N / 4; j++) {
          t[0] = uint16(a[aa + 0]) >> 0 | uint16(a[aa + 1]) << 8;
          t[1] = uint16(a[aa + 1]) >> 2 | uint16(a[aa + 2]) << 6;
          t[2] = uint16(a[aa + 2]) >> 4 | uint16(a[aa + 3]) << 4;
          t[3] = uint16(a[aa + 3]) >> 6 | uint16(a[aa + 4]) << 2;
          aa = aa + 5;
          for (let k = 0; k < 4; k++) {
            r[i][4 * j + k] = int16((t[k] & 1023) * Q + 512 >> 10);
          }
        }
      }
      return r;
    }
    // decompressV de-serializes and subsequently decompresses a polynomial,
    // representing the approximate inverse of compress2.
    // Note that compression is lossy, and thus decompression will not match the
    // original input.
    /**
     * Decompresses a Uint8Array into an array of numbers.
     *
     * @param a - The Uint8Array to decompress.
     * @returns An array of numbers.
     */
    _decompressV(a) {
      const r = new Int16Array(N);
      for (let aa = 0, i = 0; i < N / 2; i++, aa++) {
        r[2 * i + 0] = int16((a[aa] & 15) * Q + 8 >> 4);
        r[2 * i + 1] = int16((a[aa] >> 4) * Q + 8 >> 4);
      }
      return r;
    }
  };
  function polyToMsg(a) {
    const msg = new Uint8Array(32);
    let t, v;
    for (let i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        v = a[8 * i + j] - Q;
        v += v >> 31 & Q;
        t = ((uint16(v) << 1) + uint16(Q / 2)) / uint16(Q) & 1;
        msg[i] |= byte(t << j);
      }
    }
    return msg;
  }
  function polyFromMsg(msg) {
    const r = new Int16Array(N);
    let mask;
    for (let i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        mask = -1 * int16(msg[i] >> j & 1);
        r[8 * i + j] = mask & int16((Q + 1) / 2);
      }
    }
    return r;
  }
  function indcpaRejUniform(out, outOffset, buf, bufl, len) {
    let ctr = 0;
    let val0, val1;
    for (let pos = 0; ctr < len && pos + 3 <= bufl; ) {
      val0 = (uint16(buf[pos] >> 0) | uint16(buf[pos + 1]) << 8) & 4095;
      val1 = (uint16(buf[pos + 1] >> 4) | uint16(buf[pos + 2]) << 4) & 4095;
      pos = pos + 3;
      if (val0 < Q) {
        out[outOffset + ctr] = val0;
        ctr = ctr + 1;
      }
      if (ctr < len && val1 < Q) {
        out[outOffset + ctr] = val1;
        ctr = ctr + 1;
      }
    }
    return ctr;
  }
  function byteopsCbd(out, buf, eta) {
    let t, d;
    let a, b;
    for (let i = 0; i < N / 8; i++) {
      t = byteopsLoad32(buf, 4 * i);
      d = t & 1431655765;
      d = d + (t >> 1 & 1431655765);
      for (let j = 0; j < 8; j++) {
        a = int16(d >> 4 * j + 0 & 3);
        b = int16(d >> 4 * j + eta & 3);
        out[8 * i + j] = a - b;
      }
    }
  }
  function ntt(r) {
    for (let j = 0, k = 1, l = 128; l >= 2; l >>= 1) {
      for (let start = 0; start < 256; start = j + l) {
        const zeta = NTT_ZETAS[k];
        k = k + 1;
        for (j = start; j < start + l; j++) {
          const t = nttFqMul(zeta, r[j + l]);
          r[j + l] = r[j] - t;
          r[j] = r[j] + t;
        }
      }
    }
    return r;
  }
  function nttFqMul(a, b) {
    const ab = a * b;
    const u = Math.imul(ab, Q_INV) << 16 >> 16;
    return ab - u * Q >> 16;
  }
  function reduce(r) {
    for (let i = 0; i < N; i++) {
      r[i] = barrett(r[i]);
    }
    return r;
  }
  var BARRETT_V = ((1 << 24) + Q / 2) / Q;
  function barrett(a) {
    let t = BARRETT_V * a >> 24;
    t = t * Q;
    return a - t;
  }
  function polyToMont(r) {
    const f = 1353;
    for (let i = 0; i < N; i++) {
      const a = r[i] * f;
      const u = Math.imul(a, Q_INV) << 16 >> 16;
      r[i] = a - u * Q >> 16;
    }
    return r;
  }
  function multiply(a, b) {
    let r = polyBaseMulMontgomery(a[0], b[0]);
    let t;
    for (let i = 1; i < a.length; i++) {
      t = polyBaseMulMontgomery(a[i], b[i]);
      r = add(r, t);
    }
    return reduce(r);
  }
  function polyBaseMulMontgomery(a, b) {
    for (let i = 0; i < N / 4; i++) {
      const idx = 4 * i;
      const a0 = a[idx], a1 = a[idx + 1], a2 = a[idx + 2], a3 = a[idx + 3];
      const b0 = b[idx], b1 = b[idx + 1], b2 = b[idx + 2], b3 = b[idx + 3];
      const zeta = NTT_ZETAS[64 + i];
      a[idx] = nttFqMul(nttFqMul(a1, b1), zeta) + nttFqMul(a0, b0);
      a[idx + 1] = nttFqMul(a0, b1) + nttFqMul(a1, b0);
      a[idx + 2] = nttFqMul(nttFqMul(a3, b3), -zeta) + nttFqMul(a2, b2);
      a[idx + 3] = nttFqMul(a2, b3) + nttFqMul(a3, b2);
    }
    return a;
  }
  function add(a, b) {
    for (let i = 0; i < N; i++) {
      a[i] += b[i];
    }
    return a;
  }
  function subtract(a, b) {
    for (let i = 0; i < N; i++) {
      a[i] -= b[i];
    }
    return a;
  }
  function nttInverse(r) {
    let j = 0;
    for (let k = 0, l = 2; l <= 128; l <<= 1) {
      for (let start = 0; start < 256; start = j + l) {
        const zeta = NTT_ZETAS_INV[k];
        k = k + 1;
        for (j = start; j < start + l; j++) {
          const t = r[j];
          r[j] = barrett(t + r[j + l]);
          r[j + l] = t - r[j + l];
          r[j + l] = nttFqMul(zeta, r[j + l]);
        }
      }
    }
    for (j = 0; j < 256; j++) {
      r[j] = nttFqMul(r[j], NTT_ZETAS_INV[127]);
    }
    return r;
  }

  // node_modules/mlkem/esm/src/mlKem1024Base.js
  var MlKem1024Base = class extends MlKemBase {
    constructor() {
      super();
      Object.defineProperty(this, "_k", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 4
      });
      Object.defineProperty(this, "_du", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 11
      });
      Object.defineProperty(this, "_dv", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 5
      });
      Object.defineProperty(this, "_eta1", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 2
      });
      Object.defineProperty(this, "_eta2", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 2
      });
      this._skSize = 12 * this._k * N / 8;
      this._pkSize = this._skSize + 32;
      this._compressedUSize = this._k * this._du * N / 8;
      this._compressedVSize = this._dv * N / 8;
      this._initPool();
    }
    // compressU lossily compresses and serializes a vector of polynomials.
    /**
     * Lossily compresses and serializes a vector of polynomials.
     *
     * @param u - The vector of polynomials to compress.
     * @returns The compressed and serialized data as a Uint8Array.
     */
    _compressU(r, u) {
      const t = new Array(8);
      for (let rr = 0, i = 0; i < this._k; i++) {
        for (let j = 0; j < N / 8; j++) {
          for (let k = 0; k < 8; k++) {
            t[k] = uint16(((uint32(u[i][8 * j + k]) << 11) + uint32(Q / 2)) / uint32(Q) & 2047);
          }
          r[rr++] = byte(t[0] >> 0);
          r[rr++] = byte(t[0] >> 8 | t[1] << 3);
          r[rr++] = byte(t[1] >> 5 | t[2] << 6);
          r[rr++] = byte(t[2] >> 2);
          r[rr++] = byte(t[2] >> 10 | t[3] << 1);
          r[rr++] = byte(t[3] >> 7 | t[4] << 4);
          r[rr++] = byte(t[4] >> 4 | t[5] << 7);
          r[rr++] = byte(t[5] >> 1);
          r[rr++] = byte(t[5] >> 9 | t[6] << 2);
          r[rr++] = byte(t[6] >> 6 | t[7] << 5);
          r[rr++] = byte(t[7] >> 3);
        }
      }
      return r;
    }
    // compressV lossily compresses and subsequently serializes a polynomial.
    /**
     * Lossily compresses and serializes a polynomial.
     *
     * @param r - The output buffer to store the compressed data.
     * @param v - The polynomial to compress.
     * @returns The compressed and serialized data as a Uint8Array.
     */
    _compressV(r, v) {
      const t = new Uint8Array(8);
      for (let rr = 0, i = 0; i < N / 8; i++) {
        for (let j = 0; j < 8; j++) {
          t[j] = byte(((uint32(v[8 * i + j]) << 5) + uint32(Q / 2)) / uint32(Q)) & 31;
        }
        r[rr++] = byte(t[0] >> 0 | t[1] << 5);
        r[rr++] = byte(t[1] >> 3 | t[2] << 2 | t[3] << 7);
        r[rr++] = byte(t[3] >> 1 | t[4] << 4);
        r[rr++] = byte(t[4] >> 4 | t[5] << 1 | t[6] << 6);
        r[rr++] = byte(t[6] >> 2 | t[7] << 3);
      }
      return r;
    }
    // decompressU de-serializes and decompresses a vector of polynomials and
    // represents the approximate inverse of compress1. Since compression is lossy,
    // the results of decompression will may not match the original vector of polynomials.
    /**
     * Deserializes and decompresses a vector of polynomials.
     * This is the approximate inverse of the `_compressU` method.
     * Since compression is lossy, the decompressed data may not match the original vector of polynomials.
     *
     * @param a - The compressed and serialized data as a Uint8Array.
     * @returns The decompressed vector of polynomials.
     */
    _decompressU(a) {
      const r = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        r[i] = new Int16Array(N);
      }
      const t = new Array(8);
      for (let aa = 0, i = 0; i < this._k; i++) {
        for (let j = 0; j < N / 8; j++) {
          t[0] = uint16(a[aa + 0]) >> 0 | uint16(a[aa + 1]) << 8;
          t[1] = uint16(a[aa + 1]) >> 3 | uint16(a[aa + 2]) << 5;
          t[2] = uint16(a[aa + 2]) >> 6 | uint16(a[aa + 3]) << 2 | uint16(a[aa + 4]) << 10;
          t[3] = uint16(a[aa + 4]) >> 1 | uint16(a[aa + 5]) << 7;
          t[4] = uint16(a[aa + 5]) >> 4 | uint16(a[aa + 6]) << 4;
          t[5] = uint16(a[aa + 6]) >> 7 | uint16(a[aa + 7]) << 1 | uint16(a[aa + 8]) << 9;
          t[6] = uint16(a[aa + 8]) >> 2 | uint16(a[aa + 9]) << 6;
          t[7] = uint16(a[aa + 9]) >> 5 | uint16(a[aa + 10]) << 3;
          aa = aa + 11;
          for (let k = 0; k < 8; k++) {
            r[i][8 * j + k] = (t[k] & 2047) * Q + 1024 >> 11;
          }
        }
      }
      return r;
    }
    // decompressV de-serializes and subsequently decompresses a polynomial,
    // representing the approximate inverse of compress2.
    // Note that compression is lossy, and thus decompression will not match the
    // original input.
    /**
     * Decompresses a given polynomial, representing the approximate inverse of
     * compress2, in Uint8Array into an array of numbers.
     *
     * Note that compression is lossy, and thus decompression will not match the
     * original input.
     *
     * @param a - The Uint8Array to decompress.
     * @returns An array of numbers obtained from the decompression process.
     */
    _decompressV(a) {
      const r = new Int16Array(N);
      const t = new Array(8);
      for (let aa = 0, i = 0; i < N / 8; i++) {
        t[0] = a[aa + 0] >> 0;
        t[1] = a[aa + 0] >> 5 | a[aa + 1] << 3;
        t[2] = a[aa + 1] >> 2;
        t[3] = a[aa + 1] >> 7 | a[aa + 2] << 1;
        t[4] = a[aa + 2] >> 4 | a[aa + 3] << 4;
        t[5] = a[aa + 3] >> 1;
        t[6] = a[aa + 3] >> 6 | a[aa + 4] << 2;
        t[7] = a[aa + 4] >> 3;
        aa = aa + 5;
        for (let j = 0; j < 8; j++) {
          r[8 * i + j] = int16((t[j] & 31) * Q + 16 >> 5);
        }
      }
      return r;
    }
  };

  // node_modules/mlkem/esm/src/mlKem1024.js
  var MlKem1024 = class extends MlKem1024Base {
    /**
     * Constructs a new instance of the MlKem1024 class.
     */
    constructor() {
      super();
    }
    /**
     * Generates a keypair [publicKey, privateKey].
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @returns A kaypair [publicKey, privateKey].
     * @throws {@link MlKemError}
     */
    async generateKeyPair() {
      await this._setup();
      try {
        return this._generateKeyPairCore();
      } catch (e) {
        throw new MlKemError(e);
      }
    }
    /**
     * Derives a keypair [publicKey, privateKey] deterministically from a 64-octet seed.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param seed A 64-octet seed for the deterministic key generation.
     * @returns A kaypair [publicKey, privateKey].
     * @throws {@link MlKemError}
     */
    async deriveKeyPair(seed) {
      await this._setup();
      try {
        return this._deriveKeyPairCore(seed);
      } catch (e) {
        throw new MlKemError(e);
      }
    }
    /**
     * Generates a shared secret from the encapsulated ciphertext and the private key.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param pk A public key.
     * @param seed An optional 32-octet seed for the deterministic shared secret generation.
     * @returns A ciphertext (encapsulated public key) and a shared secret.
     * @throws {@link MlKemError}
     */
    async encap(pk, seed) {
      await this._setup();
      try {
        return this._encapCore(pk, seed);
      } catch (e) {
        throw new MlKemError(e);
      }
    }
    /**
     * Generates a ciphertext for the public key and a shared secret.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param ct A ciphertext generated by {@link encap}.
     * @param sk A private key.
     * @returns A shared secret.
     * @throws {@link MlKemError}
     */
    async decap(ct, sk) {
      await this._setup();
      try {
        return this._decapCore(ct, sk);
      } catch (e) {
        throw new MlKemError(e);
      }
    }
  };

  // src/pqc_auth_entry.js
  (function attachPqcAuth(global) {
    "use strict";
    const PUBLIC_KEY_CACHE = /* @__PURE__ */ new Map();
    const HEADER_CACHE = /* @__PURE__ */ new Map();
    const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1e3;
    const HKDF_INFO = new TextEncoder().encode("cyberarmor-kem-v1");
    let x25519SupportPromise = null;
    function bytesToBase64(bytes) {
      let binary = "";
      for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
      return btoa(binary);
    }
    function hexToBytes(hex) {
      if (!hex || typeof hex !== "string" || hex.length % 2 !== 0) {
        throw new Error("Invalid hex public key");
      }
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
      return out;
    }
    function concatBytes() {
      const parts = Array.from(arguments);
      const total = parts.reduce((sum, part) => sum + part.length, 0);
      const out = new Uint8Array(total);
      let offset = 0;
      for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
      }
      return out;
    }
    function toBigEndianUint32(value) {
      const buf = new ArrayBuffer(4);
      new DataView(buf).setUint32(0, value, false);
      return new Uint8Array(buf);
    }
    function resolvePublicKeyUrl(baseUrl) {
      const parsed = new URL(String(baseUrl || "").trim());
      parsed.pathname = "/pki/public-key";
      parsed.search = "";
      parsed.hash = "";
      return parsed.toString();
    }
    async function supportsX25519() {
      if (!global.crypto || !global.crypto.subtle) return false;
      if (!x25519SupportPromise) {
        x25519SupportPromise = global.crypto.subtle.generateKey(
          { name: "X25519" },
          true,
          ["deriveBits"]
        ).then(() => true).catch(() => false);
      }
      return x25519SupportPromise;
    }
    async function fetchPublicKeyInfo(baseUrl, timeoutMs) {
      const publicKeyUrl = resolvePublicKeyUrl(baseUrl);
      const cached = PUBLIC_KEY_CACHE.get(publicKeyUrl);
      if (cached && cached.expiresAt > Date.now()) return cached.info;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(publicKeyUrl, {
          method: "GET",
          headers: { Accept: "application/json" },
          signal: controller.signal
        });
        if (!response.ok) throw new Error(`Public key fetch failed: HTTP ${response.status}`);
        const info = await response.json();
        PUBLIC_KEY_CACHE.set(publicKeyUrl, {
          info,
          expiresAt: Date.now() + DEFAULT_CACHE_TTL_MS
        });
        return info;
      } finally {
        clearTimeout(timer);
      }
    }
    async function deriveX25519SharedSecret(serverPublicKeyBytes) {
      const subtle = global.crypto.subtle;
      const ephemeral = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
      const rawEphemeralPublic = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
      const importedServerPublic = await subtle.importKey(
        "raw",
        serverPublicKeyBytes,
        { name: "X25519" },
        false,
        []
      );
      const rawShared = await subtle.deriveBits(
        { name: "X25519", public: importedServerPublic },
        ephemeral.privateKey,
        256
      );
      const hkdfKey = await subtle.importKey("raw", rawShared, "HKDF", false, ["deriveBits"]);
      const sharedSecret = new Uint8Array(await subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(0),
          info: HKDF_INFO
        },
        hkdfKey,
        256
      ));
      return { ciphertext: rawEphemeralPublic, sharedSecret };
    }
    async function deriveMlKemSharedSecret(serverPublicKeyBytes) {
      const kem = new MlKem1024();
      const [ciphertext, sharedSecret] = await kem.encap(serverPublicKeyBytes);
      return {
        ciphertext: new Uint8Array(ciphertext),
        sharedSecret: new Uint8Array(sharedSecret)
      };
    }
    async function encryptTransportPayload(apiKey, kemCiphertext, sharedSecret) {
      const subtle = global.crypto.subtle;
      const iv = global.crypto.getRandomValues(new Uint8Array(12));
      const aesKey = await subtle.importKey("raw", sharedSecret, { name: "AES-GCM" }, false, ["encrypt"]);
      const plaintext = new TextEncoder().encode(apiKey);
      const encrypted = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext));
      const tag = encrypted.slice(encrypted.length - 16);
      const ciphertext = encrypted.slice(0, encrypted.length - 16);
      const payload = concatBytes(
        toBigEndianUint32(kemCiphertext.length),
        kemCiphertext,
        iv,
        ciphertext,
        tag
      );
      return `PQC:${bytesToBase64(payload)}`;
    }
    async function encryptMlKemHeader(apiKey, publicKeyHex) {
      const serverPublicKeyBytes = hexToBytes(publicKeyHex);
      const derived = await deriveMlKemSharedSecret(serverPublicKeyBytes);
      return encryptTransportPayload(apiKey, derived.ciphertext, derived.sharedSecret);
    }
    async function encryptX25519Header(apiKey, publicKeyHex) {
      const serverPublicKeyBytes = hexToBytes(publicKeyHex);
      if (serverPublicKeyBytes.length !== 32) {
        throw new Error("Unsupported X25519 public key");
      }
      const derived = await deriveX25519SharedSecret(serverPublicKeyBytes);
      return encryptTransportPayload(apiKey, derived.ciphertext, derived.sharedSecret);
    }
    async function getAuthHeaderValue(options) {
      const result = await getAuthHeaderResult(options);
      return result.value;
    }
    async function getAuthHeaderResult(options) {
      const apiKey = options && typeof options.apiKey === "string" ? options.apiKey : "";
      if (!apiKey) return { value: "", mode: "missing", algorithm: "none" };
      if (apiKey.startsWith("PQC:")) {
        return { value: apiKey, mode: "precomputed_pqc", algorithm: "precomputed" };
      }
      if (options?.pqcEnabled === false) {
        return { value: apiKey, mode: "plaintext_fallback", algorithm: "disabled" };
      }
      const strict = options?.strict === true;
      const baseUrl = options?.baseUrl || options?.controlPlaneUrl;
      if (!baseUrl) return { value: apiKey, mode: "plaintext_fallback", algorithm: "no_base_url" };
      try {
        const info = await fetchPublicKeyInfo(baseUrl, options?.timeoutMs || 3e3);
        const publicKeyHex = info?.kem_public_key;
        if (!publicKeyHex) throw new Error("Missing kem_public_key");
        const algorithm = String(info?.algorithm || "").toUpperCase();
        const cacheKey = `${baseUrl}::${algorithm}::${publicKeyHex}::${apiKey}`;
        const cachedHeader = HEADER_CACHE.get(cacheKey);
        if (cachedHeader && cachedHeader.expiresAt > Date.now()) {
          return { ...cachedHeader.info, cached: true };
        }
        let value;
        let mode;
        if (algorithm.includes("ML-KEM-1024")) {
          value = await encryptMlKemHeader(apiKey, publicKeyHex);
          mode = "native_ml_kem";
        } else {
          if (!await supportsX25519()) throw new Error("X25519 Web Crypto support unavailable");
          value = await encryptX25519Header(apiKey, publicKeyHex);
          mode = "x25519_fallback";
        }
        const infoRecord = { value, mode, algorithm: algorithm || "unknown", cached: false };
        HEADER_CACHE.set(cacheKey, {
          info: infoRecord,
          expiresAt: Date.now() + (options?.cacheTtlMs || DEFAULT_CACHE_TTL_MS)
        });
        return infoRecord;
      } catch (error) {
        if (strict) throw error;
        return {
          value: apiKey,
          mode: "plaintext_fallback",
          algorithm: "fallback",
          error: error instanceof Error ? error.message : String(error)
        };
      }
    }
    async function buildHeaders(options) {
      const headers = { ...options?.headers || {} };
      const result = await getAuthHeaderResult(options);
      if (result.value) headers["x-api-key"] = result.value;
      return { headers, authInfo: result };
    }
    global.CyberArmorPQCAuth = {
      getAuthHeaderValue,
      getAuthHeaderResult,
      buildHeaders
    };
  })(typeof self !== "undefined" ? self : window);
})();
/*! Bundled license information:

mlkem/esm/src/sha3/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
