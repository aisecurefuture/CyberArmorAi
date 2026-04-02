import type { MlKemInterface } from "./interfaces.js";
import { MlKemBase } from "./mlKemBase.js";
/**
 * Synchronous implementation of MlKem768.
 *
 * Use {@link createMlKem768} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { createMlKem768 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { createMlKem768 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = await createMlKem768();
 * const [pkR, skR] = recipient.generateKeyPair();
 *
 * const sender = await createMlKem768();
 * const [ct, ssS] = sender.encap(pkR);
 *
 * const ssR = recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export declare class MlKem768Impl extends MlKemBase implements MlKemInterface {
    _k: number;
    _du: number;
    _dv: number;
    _eta1: number;
    _eta2: number;
    constructor();
    /** Generates a keypair [publicKey, privateKey]. */
    generateKeyPair(): [Uint8Array, Uint8Array];
    /** Derives a keypair [publicKey, privateKey] deterministically from a 64-octet seed. */
    deriveKeyPair(seed: Uint8Array): [Uint8Array, Uint8Array];
    /** Encapsulates: returns [ciphertext, sharedSecret]. */
    encap(pk: Uint8Array, seed?: Uint8Array): [Uint8Array, Uint8Array];
    /** Decapsulates: returns sharedSecret. */
    decap(ct: Uint8Array, sk: Uint8Array): Uint8Array;
    /** @internal */
    static _create(): Promise<MlKem768Impl>;
}
/**
 * Creates a pre-initialized MlKem768 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link MlKemInterface} instance.
 *
 * @example
 *
 * ```ts
 * const ctx = await createMlKem768();
 * const [pk, sk] = ctx.generateKeyPair();       // sync
 * const [ct, ssS] = ctx.encap(pk);              // sync
 * const ssR = ctx.decap(ct, sk);                // sync
 * ```
 */
export declare function createMlKem768(): Promise<MlKemInterface>;
//# sourceMappingURL=mlKem768Impl.d.ts.map