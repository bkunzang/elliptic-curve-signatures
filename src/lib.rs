use elliptic_curve::{generic_array::GenericArray, Field, Group};
use sha2::digest::generic_array::typenum::U32;
use sha2::{Digest, Sha256};

mod musig;

pub fn hash<T: Group>(inputs: Vec<&[u8]>) -> T::Scalar {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input)
    }
    let hash = hasher.finalize();
    let mut scalar = <T::Scalar as Field>::ZERO;
    let scalar256 = <T::Scalar as From<u64>>::from(256);
    for byte in hash {
        scalar *= scalar256; // TODO: Maybe do this by doubling?
        scalar += <T::Scalar as From<u64>>::from(byte as u64)
    }
    scalar
}

fn hash_to_scalar<T: Group>(hash: GenericArray<u8, U32>) -> T::Scalar {
    let mut scalar = <T::Scalar as Field>::ZERO;
    let scalar256 = <T::Scalar as From<u64>>::from(256);
    for byte in hash {
        scalar *= scalar256; // TODO: Maybe do this by doubling?
        scalar += <T::Scalar as From<u64>>::from(byte as u64)
    }
    scalar
}
