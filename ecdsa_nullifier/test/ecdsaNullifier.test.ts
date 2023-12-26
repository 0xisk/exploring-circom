var EC = require("elliptic").ec;

const circomWasmTester = require("circom_tester").wasm;
import * as path from "path";
import { secp256k1 } from "@noble/curves/secp256k1";
import * as mod from '@noble/curves/abstract/modular'
import * as utils from '@noble/curves/abstract/utils'
import { calculatePrecomputes, getEffEcdsaCircuitInput, hasher, splitToRegisters } from "../utils";

const ec = new EC("secp256k1");

describe("ECDSA Nullifier", () => {
    test("should calculate witness for ecdsa nullifier", async () => {
        const circuit = await circomWasmTester(
            path.join(__dirname, "../src/ecdsa_nullifier.circom"),
            {
                prime: "secq256k1"
            }
        )

        const privKey = secp256k1.utils.randomPrivateKey();
        const privKeyBuffer = Buffer.from(privKey);
        const pubKey = secp256k1.getPublicKey(privKey);

        const privKey_2 = Buffer.from(
            "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
            "hex"
        );
        const pubKey_2 = ec.keyFromPrivate(privKey_2.toString("hex")).getPublic();

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
        const secret = 1n;

        // const Qa = [
        //     ...splitToRegisters(),
        //     ...splitToRegisters(pubkeyPoint.toAffine().y)
        // ];

        const nullifier = await hasher([pubkeyPoint.toAffine().x, pubkeyPoint.toAffine().y, secret]);

        const nullifierMessage = Buffer.from("Hello World");
        const circuitInput = getEffEcdsaCircuitInput(privKey_2, nullifierMessage);
        const nullifier_2 = await hasher([pubKey_2.x.toString(), pubKey_2.y.toString(), secret]);
        
        const inputs = {
            s: circuitInput.s,
            Tx: circuitInput.Tx,
            Ty: circuitInput.Ty,
            Ux: circuitInput.Ux,
            Uy: circuitInput.Uy,
            secret
        };

        const witness: bigint[] = await circuit.calculateWitness(inputs, true);

        console.log(Object.entries(JSON.parse(witness.toString())));

        await circuit.assertOut(witness, {
            pubKeyX: pubKey_2.x.toString(),
            pubKeyY: pubKey_2.y.toString(),
            nullifier: nullifier_2,
        });
    });
});
