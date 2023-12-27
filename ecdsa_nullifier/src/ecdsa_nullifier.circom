pragma circom 2.1.2;

include "../../efficient-ecdsa/src/ecdsa_to_pubkey.circom";
include "./poseidon_personaelabs/poseidon.circom";


template ECDSANullifier() {
    var nullifierInputs = 3;

    signal input s;
    signal input Tx;
    signal input Ty;
    signal input Ux;
    signal input Uy;

    signal input secret;

    signal output nullifier;
    signal output pubKeyX;
    signal output pubKeyY;

    component ecdsaToPubKey = ECDSAToPubKey();
    ecdsaToPubKey.s <== s;
    ecdsaToPubKey.Tx <== Tx;
    ecdsaToPubKey.Ty <== Ty;
    ecdsaToPubKey.Ux <== Ux;
    ecdsaToPubKey.Uy <== Uy;

    // Public key hashed with secret.
    component poseidon = Poseidon();
    poseidon.inputs[0] <== ecdsaToPubKey.pubKeyX;
    poseidon.inputs[1] <== ecdsaToPubKey.pubKeyY;

    component poseidon2  = Poseidon();
    poseidon2.inputs[0] <== poseidon.out;
    poseidon2.inputs[1] <== secret;

    //poseidon.inputs <== hashedInputs;

    nullifier <== poseidon2.out;
    pubKeyX <== ecdsaToPubKey.pubKeyX;
    pubKeyY <== ecdsaToPubKey.pubKeyY;
}

component main { public[ Tx, Ty, Ux, Uy ]} = ECDSANullifier();

