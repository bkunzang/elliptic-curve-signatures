use elliptic_curve::{Field, Group, PrimeField};
use sha2::{Digest, Sha256};

pub trait ECDSAGroup {
    type Scalar: PrimeField;

    fn generate_private_key() -> Self::Scalar;

    fn generate_public_key(sk: Self::Scalar) -> Self;

    fn sign(secret_key: Self::Scalar, message: &str) -> (Self::Scalar, Self::Scalar);

    fn verify(signature: (Self::Scalar, Self::Scalar), message: &str, public_key: Self) -> bool;
}

pub trait CurveGroup: Group {
    fn x(self) -> Self::Scalar;
    fn y(self) -> Self::Scalar;
    fn z(self) -> Self::Scalar;
}

// Hash function is incomplete
fn hash<T: Group>(message: &str) -> T::Scalar {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let mut scalars: Vec<T::Scalar> = Vec::new();
    let a: u128;
    for i in hash.chunks(16) {
        let bytes_array = i.try_into().unwrap();
        let a = u128::from_le_bytes(bytes_array);
        let a = PrimeField::from_u128(a);
        scalars.push(a);
    }
    //Todo: create scalar from u128s/bytes
    todo!()
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
        let z: Self::Scalar = hash::<Self>(message);
        let mut rng = rand::thread_rng();
        let k = <Self::Scalar as Field>::random(&mut rng);
        // Check that k != 0
        assert!(k.is_zero().unwrap_u8() == 0);
        let point = Self::generator() * k;
        let r = point.x();
        let s = k.invert().unwrap() * (z + r * sk);
        return (r, s);
    }

    fn verify(signature: (Self::Scalar, Self::Scalar), message: &str, public_key: Self) -> bool {
        assert!(public_key != T::identity());
        let (r, s) = signature;
        let z: Self::Scalar = hash::<Self>(message);
        let s_inv = s.invert().unwrap();
        let u1 = z * s_inv;
        let u2 = r * s_inv;
        let point = Self::generator() * u1 + public_key * u2;
        return point.x() == r;
    }
}
