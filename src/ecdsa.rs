use elliptic_curve::{Field, Group, group::GroupEncoding, PrimeField};
use elliptic_curves::hash;
pub trait ECDSAGroup {
    type Scalar: PrimeField;

    fn generate_private_key() -> Self::Scalar;

    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn sign(secret_key: Self::Scalar, message: &str) -> (Self::Scalar, Self::Scalar);

    fn verify(signature: (Self::Scalar, Self::Scalar), message: &str, public_key: Self) -> bool;
}

pub trait CurveGroup: Group {
    type PointScalar: PrimeField;
    fn x(self) -> Self::PointScalar;
    fn y(self) -> Self::PointScalar;
    fn z(self) -> Self::PointScalar;

    fn convert(mut x: Self::PointScalar) -> Self::Scalar {
        let mut binary_place = Self::Scalar::ONE;
        let mut res = Self::Scalar::ZERO;

        for _ in 0..Self::PointScalar::NUM_BITS {
            if x.is_odd().into() {
                x = x - Self::PointScalar::ONE;
                res += binary_place;
            }

            x = x * Self::PointScalar::TWO_INV;
            binary_place = binary_place.double();
        }
        res
    }
}

fn x<T: Group + GroupEncoding>(point: T) -> T::Scalar {
    let point_bytes  = point.to_bytes();
    let mut x: T::Scalar;
    for byte in point_bytes.as_ref().split_at(16).0 {
        x *= <T::Scalar as From<u64>>::from(256); // TODO: Maybe do this by doubling?
        x += <T::Scalar as From<u64>>::from(*byte as u64);
    }
    x
}

impl<T: CurveGroup + Group> ECDSAGroup for T {
    type Scalar = <T as Group>::Scalar;
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
        let r = <Self as CurveGroup>::convert(point.x());
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
        return <Self as CurveGroup>::convert(point.x()) == r;
    }
}
