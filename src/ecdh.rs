use elliptic_curve::{Field, Group, PrimeField};

pub trait ECDHGroup {
    type Scalar: PrimeField;

    fn generate_private_key() -> Self::Scalar;

    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn generate_secret(sk: Self::Scalar, pk: Self) -> Self;
}

impl<T: Group> ECDHGroup for T {
    type Scalar = T::Scalar;

    fn generate_private_key() -> Self::Scalar {
        let rng = rand::thread_rng();
        <Self::Scalar as Field>::random(rng)
    }

    fn generate_public_key(sk: Self::Scalar) -> Self {
        Self::generator() * sk
    }

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
