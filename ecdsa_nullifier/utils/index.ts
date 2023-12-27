var EC = require("elliptic").ec;
const BN = require("bn.js");

import { hashPersonalMessage, ecsign } from "@ethereumjs/util";
import { secp256k1 } from '@noble/curves/secp256k1'
import { buildPoseidon } from 'circomlibjs'

import * as mod from '@noble/curves/abstract/modular'
import * as utils from '@noble/curves/abstract/utils'

import { AffinePoint } from '@noble/curves/abstract/curve'
import { ProjPointType } from '@noble/curves/abstract/weierstrass'

const ec = new EC("secp256k1");

const SECP256K1_N = new BN(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    16
);

// Adapted from:
// https://github.com/personaelabs/efficient-zk-ecdsa/tree/main/scripts/utils
export const REGISTERS = 4n
export const STRIDE = 8n
export const NUM_STRIDES = 256n / STRIDE // = 32

export const splitToRegisters = (value: bigint) => {
    const registers = [] as bigint[];

    const hex = utils.numberToHexUnpadded(value).padStart(64, '0');

    for (let k = 0; k < REGISTERS; k++) {
        // 64bit = 16 chars in hex
        const val = hex.slice(k * 16, (k + 1) * 16);

        registers.unshift(BigInt(`0x${val}`));
    }

    return registers;
}

export const calculatePrecomputes = (point: ProjPointType<bigint>) => {
    const precomputedPoints = [] as bigint[][][][]

    const fastPoint = secp256k1.utils.precompute(8, point)

    for (let i = 0n; i < NUM_STRIDES; i++) {
        const stride: bigint[][][] = []
        const power = 2n ** (i * STRIDE)
        for (let j = 0n; j < 2n ** STRIDE; j++) {
            const l = mod.mod(j * power, secp256k1.CURVE.n)

            let precomputedPoint: AffinePoint<bigint>
            if (l === 0n) {
                precomputedPoint = secp256k1.ProjectivePoint.ZERO.toAffine()
            } else {
                precomputedPoint = fastPoint.multiply(l).toAffine()
            }
            const x = splitToRegisters(precomputedPoint.x)
            const y = splitToRegisters(precomputedPoint.y)
            stride.push([x, y])
        }
        precomputedPoints.push(stride)
    }
    return precomputedPoints
}


export const hasher = async (inputs: bigint[]): Promise<bigint> => {
    let poseidon: any

    if (!poseidon) {
        poseidon = await buildPoseidon()
    }
    const hashed = poseidon.F.toString(poseidon(inputs))  as unknown as string;
    console.log("Hashed", hashed);

    const hasnedBigInt = BigInt(hashed);
    console.log("hasnedBigInt", hasnedBigInt);

    return hasnedBigInt
}


export interface EffECDSAPubInput {
    Tx: bigint;
    Ty: bigint;
    Ux: bigint;
    Uy: bigint;
}

/**
 * Compute the group elements T and U for efficient ecdsa
 * https://personaelabs.org/posts/efficient-ecdsa-1/
 */
export const computeEffEcdsaPubInput = (
    r: bigint,
    v: bigint,
    msgHash: Buffer
): EffECDSAPubInput => {
    const isYOdd = (v - BigInt(27)) % BigInt(2);
    const rPoint = ec.keyFromPublic(
        ec.curve.pointFromX(new BN(r), isYOdd).encode("hex"),
        "hex"
    );

    // Get the group element: -(m * r^−1 * G)
    const rInv = new BN(r).invm(SECP256K1_N);

    // w = -(r^-1 * msg)
    const w = rInv.mul(new BN(msgHash)).neg().umod(SECP256K1_N);
    // U = -(w * G) = -(r^-1 * msg * G)
    const U = ec.curve.g.mul(w);

    // T = r^-1 * R
    const T = rPoint.getPublic().mul(rInv);

    return {
        Tx: BigInt(T.getX().toString()),
        Ty: BigInt(T.getY().toString()),
        Ux: BigInt(U.getX().toString()),
        Uy: BigInt(U.getY().toString())
    };
};

export const getEffEcdsaCircuitInput = (privKey: Buffer, msg: Buffer) => {
    const msgHash = hashPersonalMessage(msg);
    const { v, r: _r, s } = ecsign(msgHash, privKey);
    const r = BigInt("0x" + _r.toString("hex"));

    const circuitPubInput = computeEffEcdsaPubInput(r, v, msgHash);
    const input = {
        s: BigInt("0x" + s.toString("hex")),
        Tx: circuitPubInput.Tx,
        Ty: circuitPubInput.Ty,
        Ux: circuitPubInput.Ux,
        Uy: circuitPubInput.Uy
    };

    return input;
};
