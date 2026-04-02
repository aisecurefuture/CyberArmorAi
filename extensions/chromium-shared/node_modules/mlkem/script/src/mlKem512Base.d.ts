import { MlKemBase } from "./mlKemBase.js";
/**
 * Shared base for MlKem512 and MlKem512Impl.
 * Contains parameter configuration and the _sampleNoise1 override.
 */
export declare class MlKem512Base extends MlKemBase {
    _k: number;
    _du: number;
    _dv: number;
    _eta1: number;
    _eta2: number;
    constructor();
    /**
     * Samples a vector of polynomials from a seed.
     * @internal
     * @param sigma - The seed.
     * @param offset - The offset.
     * @param size - The size.
     * @returns The sampled vector of polynomials.
     */
    protected _sampleNoise1(sigma: Uint8Array, offset: number, size: number): Array<Int16Array>;
}
//# sourceMappingURL=mlKem512Base.d.ts.map