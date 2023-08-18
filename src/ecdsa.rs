use elliptic_curve::{group::GroupEncoding, Field, Group, PrimeField};
use k256::ProjectivePoint;
use sha2::{Sha256, Digest};

pub trait ECDSAGroup {
    type Scalar: PrimeField;

    fn generate_private_key() -> Self::Scalar;

    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn sign(secret_key: Self::Scalar, message: &[u8]) -> (Self::Scalar, Self::Scalar);

    fn verify(signature: (Self::Scalar, Self::Scalar), message: &[u8], public_key: Self) -> bool;
}

pub trait CurveGroup: Group + GroupEncoding {
    fn x(&self) -> Vec<u8>;

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

pub fn ecdsa_hash<T: Group>(input: &[u8]) -> T::Scalar {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let mut scalar = <T::Scalar as Field>::ZERO;
    for byte in hash {
        scalar *= <T::Scalar as From<u64>>::from(256); // TODO: Maybe do this by doubling?
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
        assert!(public_key != T::identity());
        let (r, s) = signature;
        let z: Self::Scalar = ecdsa_hash::<T>(message);
        let s_inv = s.invert().unwrap();
        let u1 = z * s_inv;
        let u2 = r * s_inv;
        let point = Self::generator() * u1 + public_key * u2;
        return point.convert() == r;
    }
}

impl CurveGroup for ProjectivePoint {
    fn x(&self) -> Vec<u8> {
        let bytes = self.to_bytes();

        let bytes: &[u8] = bytes.as_ref();

        let size = 32;

        // NOTE: this is a hack that depends on the k256 implementation so probably should not be
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

    fn get_random_message(length: usize) -> String {
        let message: Vec<char> = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        let message2 = message.into_iter().collect::<String>();
        message2
    }

    fn ecdsa_test_true_aux() {
        let sk = ProjectivePoint::generate_private_key();
        let pk = ProjectivePoint::generator() * sk;
        let message = get_random_message(10);
        let message_bytes = message.as_bytes();


        let signature = ProjectivePoint::sign(sk, message_bytes.as_ref());

        let verifier = ProjectivePoint::verify(signature, message_bytes.as_ref(), pk);

        assert_eq!(verifier, true);
    }

    fn ecdsa_test_false_aux() {
        let sk = ProjectivePoint::generate_private_key();
        let pk = ProjectivePoint::generator() * sk;
        let message = get_random_message(10);
        let message_bytes = message.as_bytes();

        let message_altered = get_random_message(11);
        let message_altered_bytes = message_altered.as_bytes();

        let signature = ProjectivePoint::sign(sk, message_bytes.as_ref());

        let verifier = ProjectivePoint::verify(signature, message_altered_bytes.as_ref(), pk);

        assert_eq!(verifier, false);
    }
}

