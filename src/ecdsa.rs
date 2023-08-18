use elliptic_curve::{group::GroupEncoding, Field, Group, PrimeField};
use k256::ProjectivePoint;
use sha2::{Digest, Sha256};

// Requires the implementations of methods to create ECDSA signatures
pub trait ECDSAGroup {
    type Scalar: PrimeField;

    fn generate_private_key() -> Self::Scalar;

    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn sign(secret_key: Self::Scalar, message: &[u8]) -> (Self::Scalar, Self::Scalar);

    fn verify(signature: (Self::Scalar, Self::Scalar), message: &[u8], public_key: Self) -> bool;
}

// Provides methods to extract the x coordinate from an elliptic curve point and convert that coordinate into an element of the scalar field.
pub trait CurveGroup: Group + GroupEncoding {
    // This function must be implemented for any curve that you are using with this code (see below for an example with k256::ProjectivePoint)
    fn x(&self) -> Vec<u8>;

    // Take bytes of x coordinate and convert to a scalar
    fn convert(&self) -> Self::Scalar {
        let x_bytes = self.x();

        let mut place = Self::Scalar::ONE;
        let mut res = Self::Scalar::ZERO;

        let mut buf = [0u8; 16];

        let mut factor = Self::Scalar::ONE;
        for _ in 0..128 {
            factor = factor.double();
        }

        for chunk in x_bytes.chunks(16) {
            buf.copy_from_slice(chunk);
            let num = u128::from_le_bytes(buf);
            let scalar = Self::Scalar::from_u128(num);
            res += place * scalar;

            place *= factor;
        }
        res
    }
}

// Hash a message to be signed and return a scalar.
pub fn ecdsa_hash<T: Group>(input: &[u8]) -> T::Scalar {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let mut factor = T::Scalar::ONE;
    // Create a scalar with value 2^8
    for _ in 0..8 {
        factor = factor.double()
    }
    let mut scalar = <T::Scalar as Field>::ZERO;
    // Construct a scalar from each byte
    for byte in hash {
        scalar *= factor;
        scalar += <T::Scalar as From<u64>>::from(byte as u64)
    }
    scalar
}

impl<T: CurveGroup> ECDSAGroup for T {
    type Scalar = T::Scalar;
    fn generate_private_key() -> Self::Scalar {
        let rng = rand::thread_rng();
        <Self::Scalar as Field>::random(rng)
    }

    fn generate_public_key(sk: Self::Scalar) -> Self {
        Self::generator() * sk
    }

    fn sign(sk: Self::Scalar, message: &[u8]) -> (Self::Scalar, Self::Scalar) {
        // Need to take leftmost bits of z, todo (also in verifier)
        let z: Self::Scalar = ecdsa_hash::<T>(message);
        let mut rng = rand::thread_rng();
        let k = <Self::Scalar as Field>::random(&mut rng);
        // Check that k != 0
        assert!(k.is_zero().unwrap_u8() == 0);
        let point = Self::generator() * k;
        //let point_bytes = point.to_bytes();
        let r = point.convert();
        //let r = <Self as CurveGroup>::convert(x_bytes);
        let s = k.invert().unwrap() * (z + r * sk);
        return (r, s);
    }

    fn verify(signature: (Self::Scalar, Self::Scalar), message: &[u8], public_key: Self) -> bool {
        assert!(public_key != Self::identity());
        let (r, s) = signature;
        let z: Self::Scalar = ecdsa_hash::<T>(message);
        let s_inv = s.invert().unwrap();
        let u1 = z * s_inv;
        let u2 = r * s_inv;
        let point = Self::generator() * u1 + public_key * u2;
        assert!(point != Self::identity());
        return point.convert() == r;
    }
}

impl CurveGroup for ProjectivePoint {
    fn x(&self) -> Vec<u8> {
        let bytes = self.to_bytes();

        let bytes: &[u8] = bytes.as_ref();

        let size = 32;

        // NOTE: this is a hack that depends on the k256 implementation so probably should not be
        // Curve points are stored as an x coordinate with a tag to indicate sign; the sign is the first byte and the x coordinate is the remaining 32 bytes.
        assert_eq!(bytes.as_ref().len(), 1 + size);
        let (start, end) = (1, 1 + size);

        let mut res = vec![0u8; size];

        res.copy_from_slice(&bytes[start..end]);
        res
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::ProjectivePoint;
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    #[test]
    fn ecdsa_test_true() {
        for _ in 1..100 {
            ecdsa_test_true_aux()
        }
    }

    #[test]
    fn ecdsa_test_false() {
        for _ in 1..100 {
            ecdsa_test_false_aux()
        }
    }

    fn generate_random_signer() -> (<ProjectivePoint as Group>::Scalar, ProjectivePoint) {
        let sk = ProjectivePoint::generate_private_key();
        let pk = ProjectivePoint::generator() * sk;

        (sk, pk)
    }

    // Generates a random string to use as a message in tests
    fn get_random_message(length: usize) -> String {
        let message: Vec<char> = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        let message2 = message.into_iter().collect::<String>();
        message2
    }

    // Tests whether a random message verifies correctly for a random signer
    fn ecdsa_test_true_aux() {
        let (sk, pk) = generate_random_signer();

        let message = get_random_message(10);
        let message_bytes = message.as_bytes();

        let signature = ProjectivePoint::sign(sk, message_bytes.as_ref());

        let verifier = ProjectivePoint::verify(signature, message_bytes.as_ref(), pk);

        assert_eq!(verifier, true);
    }

    // Tests whether a random message replaced by a random message with a different length (cannot be the same as the original) correctly fails to verify.
    fn ecdsa_test_false_aux() {
        let (sk, pk) = generate_random_signer();

        let message = get_random_message(10);
        let message_bytes = message.as_bytes();
        
        //Create 11 character message that must be different from the original message
        let message_altered = get_random_message(11);
        let message_altered_bytes = message_altered.as_bytes();

        let signature = ProjectivePoint::sign(sk, message_bytes.as_ref());

        let verifier = ProjectivePoint::verify(signature, message_altered_bytes.as_ref(), pk);

        assert_eq!(verifier, false);
    }
}
