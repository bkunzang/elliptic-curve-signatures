use elliptic_curve::{group::GroupEncoding, Field, Group, PrimeField};
//use sha2::{Digest, Sha256};
use elliptic_curves::hash;
pub trait SchnorrGroup {
    type Scalar: PrimeField;
    fn generate_private_key() -> Self::Scalar;
    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn sign(sk: Self::Scalar, message: &str) -> (Self::Scalar, Self);

    fn verify(signature: (Self::Scalar, Self), pk: Self, message: &str) -> bool;
}

/* fn hash<T: Group>(message: &[u8], pk: &[u8], R: &[u8]) -> T::Scalar {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.update(pk);
    hasher.update(R);
    let hash = hasher.finalize();
    let mut scalar = <T::Scalar as Field>::ZERO;
    for byte in hash {
        scalar *= <T::Scalar as From<u64>>::from(256); // TODO: Maybe do this by doubling?
        scalar += <T::Scalar as From<u64>>::from(byte as u64)
    }
    scalar
} */

impl<T: Group + GroupEncoding> SchnorrGroup for T {
    type Scalar = <Self as Group>::Scalar;
    fn generate_private_key() -> Self::Scalar {
        let rng = rand::thread_rng();
        <Self::Scalar as Field>::random(rng)
    }

    fn generate_public_key(sk: Self::Scalar) -> T {
        Self::generator() * sk
    }

    fn sign(sk: Self::Scalar, message: &str) -> (Self::Scalar, Self) {
        let r = Self::generate_private_key();
        let R = Self::generate_public_key(r);
        let R_bytes = R.to_bytes();
        let pk = Self::generate_public_key(sk).to_bytes();
        let inputs = vec![message.as_bytes(), pk.as_ref(), R_bytes.as_ref()];
        //let (R_hash, pk_hash) = (R_bytes.as_ref(), pk.as_ref());
        let hash = hash::<T>(inputs);
        let s = r + sk * hash;
        (s, R)
    }

    fn verify(signature: (Self::Scalar, Self), pk: Self, message: &str) -> bool {
        let (s, R) = signature;
        let (pk_bytes, R_bytes) = (pk.to_bytes(), R.to_bytes());
        let inputs = vec![message.as_bytes(), pk_bytes.as_ref(), R_bytes.as_ref()];
        let hash = hash::<T>(inputs);
        //let hash = hash::<T>(message.as_bytes(), pk_bytes.as_ref(), R_bytes.as_ref());
        return Self::generator() * s == (R + pk * hash);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::ProjectivePoint;
    use rand::distributions::Alphanumeric;
    use rand::{self, Rng};

    #[test]
    fn schnorr_test_true() {
        for _ in 1..100 {
            schnorr_test_true_aux()
        }
    }

    #[test]
    fn schnorr_test_false() {
        for _ in 1..100 {
            schnorr_test_false_aux()
        }
    }

    fn get_random_message(length: usize) -> String {
        let message: Vec<char> = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        let message2 = message.into_iter().collect::<String>();
        message2
    }

    fn schnorr_test_true_aux() {
        let sk = ProjectivePoint::generate_private_key();
        let pk = ProjectivePoint::generate_public_key(sk);
        let message_string = get_random_message(10);
        let message = message_string.as_str();
        let signature = ProjectivePoint::sign(sk, message);
        let verifier = ProjectivePoint::verify(signature, pk, message);
        assert_eq!(verifier, true);
    }

    fn schnorr_test_false_aux() {
        let sk = ProjectivePoint::generate_private_key();
        let pk = ProjectivePoint::generate_public_key(sk);
        let message_string = get_random_message(10);
        let message = message_string.as_str();
        let message_altered_string = get_random_message(15);
        let message_altered = message_altered_string.as_str();
        let signature = ProjectivePoint::sign(sk, message);
        let verifier = ProjectivePoint::verify(signature, pk, message_altered);
        assert_eq!(verifier, false);
    }
}
