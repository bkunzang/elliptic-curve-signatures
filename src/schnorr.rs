use elliptic_curve::{group::GroupEncoding, Field, Group, PrimeField};
use elliptic_curves::hash;
pub trait SchnorrGroup {
    type Scalar: PrimeField;

    fn generate_private_key() -> Self::Scalar;

    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn sign(sk: Self::Scalar, message: &str) -> (Self::Scalar, Self);

    fn verify(signature: (Self::Scalar, Self), pk: Self, message: &str) -> bool;
}

impl<T: Group + GroupEncoding> SchnorrGroup for T {
    type Scalar = <Self as Group>::Scalar;
    fn generate_private_key() -> Self::Scalar {
        // generate random scalar
        let rng = rand::thread_rng();
        <Self::Scalar as Field>::random(rng)
    }

    fn generate_public_key(sk: Self::Scalar) -> T {
        // public key = secret key * generator
        Self::generator() * sk
    }

    fn sign(sk: Self::Scalar, message: &str) -> (Self::Scalar, Self) {
        // r is a random scalar to be regenerated for each signature
        let r = Self::generate_private_key();
        // r_point = r * generator
        let r_point = Self::generate_public_key(r);
        // convert to bytes for hashing
        let r_point_bytes = r_point.to_bytes();
        let pk = Self::generate_public_key(sk).to_bytes();

        let inputs = vec![message.as_bytes(), pk.as_ref(), r_point_bytes.as_ref()];
        let hash = hash::<T>(inputs);

        let s = r + sk * hash;
        // signature is s and r_point
        (s, r_point)
    }

    fn verify(signature: (Self::Scalar, Self), pk: Self, message: &str) -> bool {
        let (s, r_point) = signature;
        // convert to bytes for hashing
        let (pk_bytes, r_point_bytes) = (pk.to_bytes(), r_point.to_bytes());
        let inputs = vec![
            message.as_bytes(),
            pk_bytes.as_ref(),
            r_point_bytes.as_ref(),
        ];
        let hash = hash::<T>(inputs);
        // s * G = (r + sk*hash) * G = (r * G) + (sk * G * hash) = r_point + pk * hash
        return Self::generator() * s == (r_point + pk * hash);
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

    // generates random string of characters to test signatures 
    fn get_random_message(length: usize) -> String {
        let message: Vec<char> = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        let message2 = message.into_iter().collect::<String>();
        message2
    }

    // passes unaltered randomly generated signature and message through verifier and checks if it returns true
    fn schnorr_test_true_aux() {
        let sk = ProjectivePoint::generate_private_key();
        let pk = ProjectivePoint::generate_public_key(sk);
        let message_string = get_random_message(10);
        let message = message_string.as_str();
        let signature = ProjectivePoint::sign(sk, message);
        let verifier = ProjectivePoint::verify(signature, pk, message);
        assert_eq!(verifier, true);
    }

    // passes altered message through verifier and checks if it returns false
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
