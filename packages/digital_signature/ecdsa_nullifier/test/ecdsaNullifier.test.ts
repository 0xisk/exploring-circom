var EC = require("elliptic").ec;

const circomWasmTester = require("circom_tester").wasm;
const buildPoseidon = require("circomlibjs").buildPoseidon;

import { poseidon3 } from "poseidon-lite";

import * as path from "path";
import { secp256k1 } from "@noble/curves/secp256k1";
import * as mod from '@noble/curves/abstract/modular';
import * as utils from '@noble/curves/abstract/utils';
import { calculatePrecomputes, getEffEcdsaCircuitInput, hasher, splitToRegisters } from "../utils";
import { Poseidon } from "@personaelabs/spartan-ecdsa";

const ec = new EC("secp256k1");

describe("ECDSA Nullifier", () => {
    test("should calculate the T and U", async () => {
        const privKey = secp256k1.utils.randomPrivateKey();
        const privKeyBuffer = Buffer.from(privKey);
        const pubKey = secp256k1.getPublicKey(privKey);

        const nullifierMessageHash = secp256k1.CURVE.hash("This is a Nullifier message");

        const sig = secp256k1.sign(nullifierMessageHash, privKey);

        const pubkeyPoint = secp256k1.ProjectivePoint.fromHex(pubKey);

        const { r, s } = sig;
        const m = mod.mod(utils.bytesToNumberBE(nullifierMessageHash), secp256k1.CURVE.n);
        const sInverted = mod.invert(s, secp256k1.CURVE.n); // s^-1
        const u1 = mod.mod(m * sInverted, secp256k1.CURVE.n); // u1 = hs^-1 mod n
        const u2 = mod.mod(r * sInverted, secp256k1.CURVE.n); // u2 = rs^-1 mod n

        const R = secp256k1.ProjectivePoint.BASE.multiplyAndAddUnsafe(
            pubkeyPoint,
            u1,
            u2
        ); // R' = u1⋅G + u2⋅P

        // R'.X == R.x <==> r' == r
        expect(R?.toAffine().x).toEqual(r);

        // T = r^-1 * R
        const rInverted = mod.invert(r, secp256k1.CURVE.n);
        const T = R?.multiply(rInverted);

        // U = -(r^-1) * m * G
        const u = mod.mod(
            mod.mod(-rInverted, secp256k1.CURVE.n) * utils.bytesToNumberBE(nullifierMessageHash),
            secp256k1.CURVE.n
        );
        const U = secp256k1.ProjectivePoint.BASE.multiply(u);

        const sT = T?.multiply(s);
        const recoveredPubkey = U.add(sT!).toAffine();

        // Check the recovered pubkey and the original one
        expect(recoveredPubkey.x).toEqual(pubkeyPoint.toAffine().x);
        expect(recoveredPubkey.y).toEqual(pubkeyPoint.toAffine().y);


        // Verify the signature
        const verified = secp256k1.verify(sig, nullifierMessageHash, pubKey);
        expect(verified).toEqual(true);

        const sRegisters = splitToRegisters(s);
        const URegisters = [
            splitToRegisters(U.toAffine().x),
            splitToRegisters(U.toAffine().y)
        ];
        const TPreComputes = calculatePrecomputes(T!);
    });

    test("should calculate witness for ecdsa nullifier using personaelabs poseidon", async () => {
        const poseidon = new Poseidon();
        await poseidon.initWasm();

        const poseidonCircomlib = await buildPoseidon();
        const F = poseidonCircomlib.F;

        const ecdsaNullifierCircuit = await circomWasmTester(
            path.join(__dirname, "./circuits/ecdsa_nullifier.circom")
        );

        const privKey = Buffer.from(
            "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
            "hex"
        );
        const pubKey = ec.keyFromPrivate(privKey.toString("hex")).getPublic();

        const secret = 1n;

        const nullifierMessage = Buffer.from("Hello World");
        const circuitInput = getEffEcdsaCircuitInput(privKey, nullifierMessage);

        const Qa = [
            ...splitToRegisters(pubKey.x),
            ...splitToRegisters(pubKey.y),
        ];

        // const pubkeyHashed = await poseidon.hash([pubKey.x, pubKey.y]);
        // const nullifier = await poseidon.hash([pubkeyHashed, secret]);

        const nullifier_hasher = await hasher([pubKey.x, pubKey.y, secret]);
        console.log("nullifier_hasher", nullifier_hasher);

        const nullifier = await poseidonCircomlib([pubKey.x, pubKey.y, secret]);
        const nullifierF = F.toObject(nullifier);
        console.log("nullifierF", nullifierF);

        const nullifier_poseidon_lite = poseidon3([pubKey.x, pubKey.y, secret]);
        console.log("nullifier_poseidon_lite", nullifier_poseidon_lite);

        const inputs = {
            s: circuitInput.s,
            secret,
            Tx: circuitInput.Tx,
            Ty: circuitInput.Ty,
            Ux: circuitInput.Ux,
            Uy: circuitInput.Uy,
        };

        const witness: bigint[] = await ecdsaNullifierCircuit.calculateWitness(inputs, true);

        await ecdsaNullifierCircuit.assertOut(witness, {
            pubKeyX: pubKey.x,
            pubKeyY: pubKey.y,
            nullifier: nullifierF,
        });
    });
});
