pragma circom  2.1.0;

include "./utils.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";


// A pure RLN without memebership checker
template RLN(DEPTH, LIMIT_BIT_SIZE) {
    // Private signals
    signal input identitySecret;
    signal input userMessageLimit;
    signal input messageId;

    // Public signals
    signal input x; // Hash(signal), where signal is for example message, that was sent by user;
    signal input externalNullifier; // Poseidon(epoch,rln_identifier), where rln_identifier is a random finite field value, unique per RLN app.

    // Outputs
    signal output y; // calculated first-degree linear polynomial (y=kx+b);
    signal output nullifier; // internal nullifier/pseudonym of the user in anonyomus environment;

    signal identityCommitment <== Poseidon(1)([identitySecret]);
    signal rateCommitment <== Poseidon(2)([identityCommitment, userMessageLimit]);

    // MessageId range check
    RangeCheck(LIMIT_BIT_SIZE)(messageId, userMessageLimit);

    // SSS share calculation
    signal a1 <== Poseidon(3)([identitySecret, externalNullifier, messageId]);
    y <== a1 * x + identitySecret; // A(x) = a1 ∗ x + a0

    // Nullifier Calculation
    nullifier <== Poseidon(1)([a1]);
}

component main { public [x, externalNullifier] } = RLN(20, 16);
