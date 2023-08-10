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
    type PointScalar: PrimeField;
    fn x(self) -> Self::PointScalar;
    fn y(self) -> Self::PointScalar;
    fn z(self) -> Self::PointScalar;

    fn convert(mut x: Self::PointScalar) -> Self::Scalar {
        let num_bits = Self::PointScalar::NUM_BITS as usize;

        let mut bits = Vec::with_capacity(num_bits);

        // Populate `bits` with the little-endian bits of `x`.
        // This is equivalent to `PrimeFieldBits::to_le_bits()`.
        for _ in 0..num_bits {
            let bit: bool = x.is_odd().into();
            bits.push(bit);

            if bit {
                x = x - Self::PointScalar::ONE;
            }

            x = x * Self::PointScalar::TWO_INV;
        }

        bits.reverse();

        let mut res = Self::Scalar::ZERO;

        for bit in bits {
            res = res.double();

            if bit {
                res += Self::Scalar::ONE;
            };
        }

        res
    }
}

// Hash function is incomplete
fn hash<T: Group>(message: &str) -> T::Scalar {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    let mut scalar = <T::Scalar as Field>::ZERO;
    for byte in hash {
        // TODO: Maybe this is big endian instead of little endian?
        scalar *= <T::Scalar as From<u64>>::from(256); // TODO: Maybe do this by doubling?
        scalar += <T::Scalar as From<u64>>::from(byte as u64)
    }
    // let mut scalars: Vec<T::Scalar> = Vec::new();
    // let a: u128;
    // for i in hash.chunks(16) {
    //     let bytes_array = i.try_into().unwrap();
    //     let a = u128::from_le_bytes(bytes_array);
    //     let a = PrimeField::from_u128(a);
    //     scalars.push(a);
    // }
    //Todo: create scalar from u128s/bytes
    scalar // TODO: Generate test vectors from the Sage script and compare with this output
}
// int.from_bytes(hash)
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
        let z: Self::Scalar = hash::<Self>(message);
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
        let z: Self::Scalar = hash::<Self>(message);
        let s_inv = s.invert().unwrap();
        let u1 = z * s_inv;
        let u2 = r * s_inv;
        let point = Self::generator() * u1 + public_key * u2;
        return <Self as CurveGroup>::convert(point.x()) == r;
    }
}
