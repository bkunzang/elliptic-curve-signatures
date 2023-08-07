
use elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand::Rng;

const G: ProjectivePoint = ProjectivePoint::GENERATOR;

pub fn generate_private_key() -> Scalar {
    let mut rng = rand::thread_rng();
    let sk = Scalar::random(&mut rng);
    sk
}

pub fn generate_public_key(sk: Scalar) -> ProjectivePoint {
   G * sk
}

pub fn generate_secret(sk: Scalar, pk: ProjectivePoint) -> ProjectivePoint {
    pk * sk
}

#[cfg(test)]
mod test {
use super::*;

#[test]
fn ecdh_test() {
    for _ in 1..100 {
        ecdh_test_aux()
    }
}

fn ecdh_test_aux() {
    let sk_a = generate_private_key();
    let pk_a = generate_public_key(sk_a);

    let sk_b = generate_private_key();
    let pk_b = generate_public_key(sk_b);

    let secret_a = generate_secret(sk_a, pk_b);
    let secret_b = generate_secret(sk_b, pk_a);

    assert_eq!(secret_a, secret_b);
}
}