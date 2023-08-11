use elliptic_curve::{Field, Group};
use sha2::{Digest, Sha256};

pub fn hash<T: Group>(inputs: Vec<&[u8]>) -> T::Scalar {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input)
    }
    let hash = hasher.finalize();
    let mut scalar = <T::Scalar as Field>::ZERO;
    for byte in hash {
        scalar *= <T::Scalar as From<u64>>::from(256); // TODO: Maybe do this by doubling?
        scalar += <T::Scalar as From<u64>>::from(byte as u64)
    }
    scalar
}