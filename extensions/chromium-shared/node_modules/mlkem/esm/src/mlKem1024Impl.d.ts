import type { MlKemInterface } from "./interfaces.js";
import { MlKem1024Base } from "./mlKem1024Base.js";
/**
 * Synchronous implementation of MlKem1024.
 *
 * Use {@link createMlKem1024} to create an initialized instance.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { createMlKem1024 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { createMlKem1024 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = await createMlKem1024();
 * const [pkR, skR] = recipient.generateKeyPair();
 *
 * const sender = await createMlKem1024();
 * const [ct, ssS] = sender.encap(pkR);
 *
 * const ssR = recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export declare class MlKem1024Impl extends MlKem1024Base implements MlKemInterface {
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
    static _create(): Promise<MlKem1024Impl>;
}
/**
 * Creates a pre-initialized MlKem1024 instance with synchronous operations.
 *
 * @returns A promise that resolves to an {@link MlKemInterface} instance.
 *
 * @example
 *
 * ```ts
 * const ctx = await createMlKem1024();
 * const [pk, sk] = ctx.generateKeyPair();       // sync
 * const [ct, ssS] = ctx.encap(pk);              // sync
 * const ssR = ctx.decap(ct, sk);                // sync
 * ```
 */
export declare function createMlKem1024(): Promise<MlKemInterface>;
//# sourceMappingURL=mlKem1024Impl.d.ts.map