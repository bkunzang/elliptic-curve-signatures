use elliptic_curve::{Field, Group, PrimeField};

// Required functions for ECDH (elliptic curve Diffie Hellman exchange)
pub trait ECDHGroup {
    type Scalar: PrimeField;

    fn generate_private_key() -> Self::Scalar;

    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn generate_secret(sk: Self::Scalar, pk: Self) -> Self;
}

impl<T: Group> ECDHGroup for T {
    type Scalar = T::Scalar;

    // Private key is a random scalar
    fn generate_private_key() -> Self::Scalar {
        let rng = rand::thread_rng();
        <Self::Scalar as Field>::random(rng)
    }
    // Pk = sk * generator (in this case an elliptic curve point)
    fn generate_public_key(sk: Self::Scalar) -> Self {
        Self::generator() * sk
    }

    // If parties A and B both have private and public keys, they can generate a shared secret as follows:
    // Secret of A: pk_b * sk_a
    // Secret of B: pk_a * sk_b
    // pk_b = sk_b * generator
    // pk_a = sk_a * generator
    // Therefore, both secrets equal sk_b * sk_a * generator and are equal
    fn generate_secret(sk: Self::Scalar, pk: Self) -> Self {
        pk * sk
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::ProjectivePoint;

    #[test]
    fn ecdh_test() {
        for _ in 1..100 {
            ecdh_test_aux()
        }
    }

    // Generate a two random signers and create a shared secret, then check that the shared secrets are equal.
    fn ecdh_test_aux() {
        let sk_a = ProjectivePoint::generate_private_key();
        let pk_a = ProjectivePoint::generate_public_key(sk_a);

        let sk_b = ProjectivePoint::generate_private_key();
        let pk_b = ProjectivePoint::generate_public_key(sk_b);

        let secret_a = ProjectivePoint::generate_secret(sk_a, pk_b);
        let secret_b = ProjectivePoint::generate_secret(sk_b, pk_a);

        assert_eq!(secret_a, secret_b);
    }
}
