pragma circom  2.1.0;

include "../../../protocols/rln/circuits/rln.circom";
include "../../efficient_ecdsa/circuits/ecdsa_pubkey_membership.circom";

template ECDSARLN(DEPTH, LIMIT_BIT_SIZE) {
    // Private inputs
    signal input s;
    signal input userMessageLimit;
    signal input messageId;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];

    // Public inputs
    signal input Tx;
    signal input Ty;
    signal input Ux;
    signal input Uy;
    signal input root;
    signal input x;
    signal input externalNullifier;

    // Outputs
    signal output y;
    signal output nullifier;

    // Check the signature public key membership and extract the address
    signal address <==  ECDSAAddrMembership(DEPTH)(S, Tx, Ty, Ux, Uy, root, pathIndices, siblings);

    // Using RLN to calculate the nullifier for that address according to the message limit and message id.
    component rln = RLN(LIMIT_BIT_SIZE);
    rln.identitySecret = address;
    rln.userMessageLimit = userMessageLimit;
    rln.messageId = messageId;
    rln.x = x;
    rln.externalNullifier = externalNullifier;

    y <== rln.y;
    nullifier <== rln.nullifier;
}

component main { public [Tx, Ty, Ux, Uy, root, x, externalNullifier] } = ECDSARLN(20, 16);
