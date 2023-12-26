pragma circom 2.1.2;

include "../../efficient-ecdsa/src/ecdsa_to_pubkey.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";


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
    component poseidon = Poseidon(nullifierInputs);
    poseidon.inputs[0] <== ecdsaToPubKey.pubKeyX;
    poseidon.inputs[1] <== ecdsaToPubKey.pubKeyY;
    poseidon.inputs[2] <== secret;

    nullifier <== poseidon.out;
    pubKeyX <== ecdsaToPubKey.pubKeyX;
    pubKeyY <== ecdsaToPubKey.pubKeyY;
}

component main { public[ Tx, Ty, Ux, Uy ]} = ECDSANullifier();

