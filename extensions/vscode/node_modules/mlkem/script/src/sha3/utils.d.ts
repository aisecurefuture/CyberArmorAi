/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/src/utils.ts
 */
/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
export declare function isBytes(a: unknown): a is Uint8Array;
/** Asserts something is positive integer. */
export declare function anumber(n: number, title?: string): void;
/** Asserts something is Uint8Array. */
export declare function abytes(value: Uint8Array, length?: number, title?: string): Uint8Array;
/** Asserts a hash instance has not been destroyed / finished */
export declare function aexists(instance: any, checkFinished?: boolean): void;
/** Asserts output is properly-sized byte array */
export declare function aoutput(out: any, instance: any): void;
/** Generic type encompassing 8/16/32-byte arrays - but not 64-byte. */
export type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array | Uint16Array | Int16Array | Uint32Array | Int32Array;
/** Cast u8 / u16 / u32 to u32. */
export declare function u32(arr: TypedArray): Uint32Array;
/** Zeroize a byte array. Warning: JS provides no guarantees. */
export declare function clean(...arrays: TypedArray[]): void;
/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
export declare const isLE: boolean;
/** The byte swap operation for uint32 */
export declare function byteSwap(word: number): number;
/** Conditionally byte swap if on a big-endian platform */
export declare const swap8IfBE: (n: number) => number;
/** @deprecated */
export declare const byteSwapIfBE: typeof swap8IfBE;
/** In place byte swap for Uint32Array */
export declare function byteSwap32(arr: Uint32Array): Uint32Array;
export declare const swap32IfBE: (u: Uint32Array) => Uint32Array;
/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
export declare function hexToBytes(hex: string): Uint8Array;
/**
 * Converts string to bytes using UTF8 encoding.
 * @example utf8ToBytes('abc') // Uint8Array.from([97, 98, 99])
 */
export declare function utf8ToBytes(str: string): Uint8Array;
/**
 * Converts bytes to string using UTF8 encoding.
 * @example bytesToUtf8(Uint8Array.from([97, 98, 99])) // 'abc'
 */
export declare function bytesToUtf8(bytes: Uint8Array): string;
/** Copies several Uint8Arrays into one. */
export declare function concatBytes(...arrays: Uint8Array[]): Uint8Array;
export interface Hash<T> {
    blockLen: number;
    outputLen: number;
    update(buf: Uint8Array): this;
    digestInto(buf: Uint8Array): void;
    digest(): Uint8Array;
    destroy(): void;
    _cloneInto(to?: T): T;
    clone(): T;
}
export interface PRG {
    addEntropy(seed: Uint8Array): void;
    randomBytes(length: number): Uint8Array;
    clean(): void;
}
/**
 * XOF: streaming API to read digest in chunks.
 * Same as 'squeeze' in keccak/k12 and 'seek' in blake3, but more generic name.
 * When hash used in XOF mode it is up to user to call '.destroy' afterwards, since we cannot
 * destroy state, next call can require more bytes.
 */
export type HashXOF<T extends Hash<T>> = Hash<T> & {
    xof(bytes: number): Uint8Array;
    xofInto(buf: Uint8Array): Uint8Array;
};
export type HasherCons<T, Opts = undefined> = Opts extends undefined ? () => T : (opts?: Opts) => T;
export type HashInfo = {
    oid?: Uint8Array;
};
/** Hash function */
export type CHash<T extends Hash<T> = Hash<any>, Opts = undefined> = {
    outputLen: number;
    blockLen: number;
} & HashInfo & (Opts extends undefined ? {
    (msg: Uint8Array): Uint8Array;
    create(): T;
} : {
    (msg: Uint8Array, opts?: Opts): Uint8Array;
    create(opts?: Opts): T;
});
/** XOF with output */
export type CHashXOF<T extends HashXOF<T> = HashXOF<any>, Opts = undefined> = CHash<T, Opts>;
export declare function createHasher<T extends Hash<T>, Opts = undefined>(hashCons: HasherCons<T, Opts>, info?: HashInfo): CHash<T, Opts>;
export declare const oidNist: (suffix: number) => {
    oid: Uint8Array;
};
//# sourceMappingURL=utils.d.ts.map