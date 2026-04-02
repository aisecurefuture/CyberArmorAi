/**
 * Represents the base class for the ML-KEM key encapsulation mechanism.
 *
 * This class provides the base implementation for the ML-KEM key encapsulation mechanism.
 *
 * @remarks
 *
 * This class is not intended to be used directly. Instead, use one of the subclasses:
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { MlKemBase } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { MlKemBase } from "mlkem"; // or "crystals-kyber-js"
 *
 * class MlKem768 extends MlKemBase {
 *   protected _k = 3;
 *   protected _du = 10;
 *   protected _dv = 4;
 *   protected _eta1 = 2;
 *   protected _eta2 = 2;
 *
 *   constructor() {
 *     super();
 *     this._skSize = 12 * this._k * N / 8;
 *     this._pkSize = this._skSize + 32;
 *     this._compressedUSize = this._k * this._du * N / 8;
 *     this._compressedVSize = this._dv * N / 8;
 *   }
 * }
 *
 * const kyber = new MlKem768();
 * ```
 */
export declare class MlKemBase {
    protected _api: Crypto | undefined;
    protected _k: number;
    protected _du: number;
    protected _dv: number;
    protected _eta1: number;
    protected _eta2: number;
    protected _skSize: number;
    protected _pkSize: number;
    protected _compressedUSize: number;
    protected _compressedVSize: number;
    private _poolG;
    private _poolH;
    private _poolKdf;
    private _poolXof;
    private _poolPrf1;
    private _poolPrf2;
    private _bufG;
    private _bufH;
    private _bufKdf;
    private _bufXof;
    private _bufPrf1;
    private _bufPrf2;
    private _nonceBuf;
    private _xofSeed;
    private _kBuf;
    private _matrixA;
    protected _noiseVecs: Array<Int16Array>;
    private _polyVec;
    private _bufPkCheck;
    private _bufCt;
    /**
     * Creates a new instance of the MlKemBase class.
     */
    constructor();
    protected _initPool(): void;
    protected _zeroPool(): void;
    private _polyToBytes;
    private _polyFromBytes;
    private _g;
    private _h;
    private _kdf;
    private _xof;
    protected _prf1(sigma: Uint8Array, nonce: number): Uint8Array;
    private _prf2;
    protected _generateKeyPairCore(): [Uint8Array, Uint8Array];
    protected _deriveKeyPairCore(seed: Uint8Array): [Uint8Array, Uint8Array];
    protected _encapCore(pk: Uint8Array, seed?: Uint8Array): [Uint8Array, Uint8Array];
    protected _decapCore(ct: Uint8Array, sk: Uint8Array): Uint8Array;
    /**
     * Sets up the MlKemBase instance by loading the necessary crypto library.
     * If the crypto library is already loaded, this method does nothing.
     * @returns {Promise<void>} A promise that resolves when the setup is complete.
     */
    protected _setup(): Promise<void>;
    /**
     * Returns a Uint8Array seed for cryptographic operations.
     * If no seed is provided, a random seed of length 32 bytes is generated.
     * If a seed is provided, it must be exactly 32 bytes in length.
     *
     * @param seed - Optional seed for cryptographic operations.
     * @returns A Uint8Array seed.
     * @throws Error if the provided seed is not 32 bytes in length.
     */
    private _getSeed;
    /**
     * Derives a key pair from a given seed.
     *
     * @param seed - The seed used for key derivation.
     * @returns An array containing the public key and secret key.
     */
    private _deriveKeyPair;
    /**
     * Derives a CPA key pair using the provided CPA seed.
     *
     * @param cpaSeed - The CPA seed used for key derivation.
     * @returns An array containing the public key and private key.
     */
    private _deriveCpaKeyPair;
    /**
     * Encapsulates a message using the ML-KEM encryption scheme.
     *
     * @param pk - The public key.
     * @param msg - The message to be encapsulated.
     * @param seed - The seed used for generating random values.
     * @returns The encapsulated message as a Uint8Array.
     */
    private _encap;
    /**
     * Decapsulates the ciphertext using the provided secret key.
     *
     * @param ct - The ciphertext to be decapsulated.
     * @param sk - The secret key used for decapsulation.
     * @returns The decapsulated message as a Uint8Array.
     */
    private _decap;
    /**
     * Generates a sample matrix based on the provided seed and transposition flag.
     *
     * @param seed - The seed used for generating the matrix.
     * @param transposed - A flag indicating whether the matrix should be transposed or not.
     * @returns The generated sample matrix.
     */
    private _sampleMatrix;
    /**
     * Generates a 2D array of noise samples.
     *
     * @param sigma - The noise parameter.
     * @param offset - The offset value.
     * @param size - The size of the array.
     * @returns The generated 2D array of noise samples.
     */
    protected _sampleNoise1(sigma: Uint8Array, offset: number, size: number): Array<Int16Array>;
    /**
     * Generates a 2-dimensional array of noise samples.
     *
     * @param sigma - The noise parameter.
     * @param offset - The offset value.
     * @param size - The size of the array.
     * @returns The generated 2-dimensional array of noise samples.
     */
    protected _sampleNoise2(sigma: Uint8Array, offset: number, size: number): Array<Int16Array>;
    /**
     * Converts a Uint8Array to a 2D array of numbers representing a polynomial vector.
     * Each element in the resulting array represents a polynomial.
     * @param a The Uint8Array to convert.
     * @returns The 2D array of numbers representing the polynomial vector.
     */
    private _polyvecFromBytes;
    /**
     * Compresses the given array of coefficients into a Uint8Array.
     *
     * @param r - The output Uint8Array.
     * @param u - The array of coefficients.
     * @returns The compressed Uint8Array.
     */
    protected _compressU(r: Uint8Array, u: Array<Int16Array>): Uint8Array;
    /**
     * Compresses the given array of numbers into a Uint8Array.
     *
     * @param r - The Uint8Array to store the compressed values.
     * @param v - The array of numbers to compress.
     * @returns The compressed Uint8Array.
     */
    protected _compressV(r: Uint8Array, v: Int16Array): Uint8Array;
    /**
     * Decompresses a Uint8Array into a two-dimensional array of numbers.
     *
     * @param a The Uint8Array to decompress.
     * @returns The decompressed two-dimensional array.
     */
    protected _decompressU(a: Uint8Array): Array<Int16Array>;
    /**
     * Decompresses a Uint8Array into an array of numbers.
     *
     * @param a - The Uint8Array to decompress.
     * @returns An array of numbers.
     */
    protected _decompressV(a: Uint8Array): Int16Array;
}
//# sourceMappingURL=mlKemBase.d.ts.map