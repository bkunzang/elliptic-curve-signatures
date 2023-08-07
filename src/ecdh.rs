use elliptic_curve::{Field, Group};
use k256;
// use rand::Rng;
use std::ops::Mul;

// const G: ProjectivePoint = ProjectivePoint::GENERATOR;

// pub fn generate_private_key() -> Scalar {
//     let mut rng = rand::thread_rng();
//     let sk = Scalar::random(&mut rng);
//     sk
// }

// pub fn generate_public_key(sk: Scalar) -> ProjectivePoint {
//     G * sk
// }

// pub fn generate_secret(sk: Scalar, pk: ProjectivePoint) -> ProjectivePoint {
//     pk * sk
// }

pub trait ECDHGroup {
    type G: Group;

    fn generate_private_key2() -> <Self::G as Group>::Scalar {
        let rng = rand::thread_rng();
        <<Self::G as Group>::Scalar as Field>::random(rng)
    }

    fn generate_public_key2(sk: <Self::G as Group>::Scalar) -> Self::G {
        <Self::G as Group>::generator().mul(sk)
    }

    fn generate_secret2(sk: <Self::G as Group>::Scalar, pk: Self::G) -> Self::G {
        pk.mul(sk)
    }
}

// impl ECDHGroup for k256::ProjectivePoint {
//     type G = k256::
// }

#[cfg(test)]
mod test {
    use super::*;

    // #[test]
    // fn ecdh_test() {
    //     for _ in 1..100 {
    //         ecdh_test_aux()
    //     }
    // }

    //     fn ecdh_test_aux() {
    //         let sk_a = generate_private_key();
    //         let pk_a = generate_public_key(sk_a);

    //         let sk_b = generate_private_key();
    //         let pk_b = generate_public_key(sk_b);

    //         let secret_a = generate_secret(sk_a, pk_b);
    //         let secret_b = generate_secret(sk_b, pk_a);

    //         assert_eq!(secret_a, secret_b);
    //     }
    // }
}
