use elliptic_curve::{group::GroupEncoding, Field, Group, PrimeField};
use elliptic_curves::hash;
use k256::ProjectivePoint;

pub trait ECDSAGroup {
    type Scalar: PrimeField;

    fn generate_private_key() -> Self::Scalar;

    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn sign(secret_key: Self::Scalar, message: &str) -> (Self::Scalar, Self::Scalar);

    fn verify(signature: (Self::Scalar, Self::Scalar), message: &str, public_key: Self) -> bool;
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

impl<T: CurveGroup> ECDSAGroup for T {
    type Scalar = T::Scalar;
    fn generate_private_key() -> Self::Scalar {
        let rng = rand::thread_rng();
        <Self::Scalar as Field>::random(rng)
    }

    fn generate_public_key(sk: Self::Scalar) -> Self {
        Self::generator() * sk
    }

    fn sign(sk: Self::Scalar, message: &str) -> (Self::Scalar, Self::Scalar) {
        // Need to take leftmost bits of z, todo (also in verifier)
        let z: Self::Scalar = hash::<Self>(vec![message.as_bytes()]);
        let mut rng = rand::thread_rng();
        let k = <Self::Scalar as Field>::random(&mut rng);
        // Check that k != 0
        assert!(k.is_zero().unwrap_u8() == 0);
        let point = Self::generator() * k;
        let point_bytes = point.to_bytes();
        let x_bytes = todo!();
        let r = <Self as CurveGroup>::convert(x_bytes);
        let s = k.invert().unwrap() * (z + r * sk);
        return (r, s);
    }

    fn verify(signature: (Self::Scalar, Self::Scalar), message: &str, public_key: Self) -> bool {
        assert!(public_key != T::identity());
        let (r, s) = signature;
        let z: Self::Scalar = hash::<Self>(vec![message.as_bytes()]);
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
        assert_eq!(bytes.as_ref().len(), 1 + 2 * size);
        let (start, end) = (1, 1 + size);

        let mut res = vec![0u8; size];

        res.copy_from_slice(&bytes[start..end]);
        res
    }
}
