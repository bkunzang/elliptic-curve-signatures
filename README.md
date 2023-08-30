# TODO:
Implementations of algorithms in elliptic curve cryptography, including Elliptic Curve Diffie Hellman Key Exchange (ECDH), ECDSA, Schnorr Signatures, and the Musig Schnorr protocol for signature aggregation.

The implementations in this repo are generic, and must be used with an external elliptic curve crate and point type, such as k256::ProjectivePoint or similar.

Note: The Musig module is more of a demonstration of the protocol and does not have the interaction between signers that a real implementation would have.

Sources:
ECDSA: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
Schnorr/Musig: https://tlu.tarilabs.com/cryptography/introduction-schnorr-signatures
