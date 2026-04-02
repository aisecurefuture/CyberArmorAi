import { MlKemBase } from "./mlKemBase.js";
/**
 * Shared base for MlKem1024 and MlKem1024Impl.
 * Contains parameter configuration and compression/decompression overrides.
 */
export declare class MlKem1024Base extends MlKemBase {
    _k: number;
    _du: number;
    _dv: number;
    _eta1: number;
    _eta2: number;
    constructor();
    /**
     * Lossily compresses and serializes a vector of polynomials.
     *
     * @param u - The vector of polynomials to compress.
     * @returns The compressed and serialized data as a Uint8Array.
     */
    protected _compressU(r: Uint8Array, u: Array<Int16Array>): Uint8Array;
    /**
     * Lossily compresses and serializes a polynomial.
     *
     * @param r - The output buffer to store the compressed data.
     * @param v - The polynomial to compress.
     * @returns The compressed and serialized data as a Uint8Array.
     */
    protected _compressV(r: Uint8Array, v: Int16Array): Uint8Array;
    /**
     * Deserializes and decompresses a vector of polynomials.
     * This is the approximate inverse of the `_compressU` method.
     * Since compression is lossy, the decompressed data may not match the original vector of polynomials.
     *
     * @param a - The compressed and serialized data as a Uint8Array.
     * @returns The decompressed vector of polynomials.
     */
    protected _decompressU(a: Uint8Array): Array<Int16Array>;
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
    protected _decompressV(a: Uint8Array): Int16Array;
}
//# sourceMappingURL=mlKem1024Base.d.ts.map