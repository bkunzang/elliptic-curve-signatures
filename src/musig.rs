use std::collections::HashMap;

use elliptic_curve::{group::GroupEncoding, Field, Group, PrimeField};
use elliptic_curves::hash;

// Signer
// MuSig
// Commitment
// Signature

// round_1 -> (a_map, x)
// round_2 -> bool
// round_3 -> Signature

enum MultiSig<G: Group> {
    R0(MuSig<G>),
    R1(MuSig<G>),
    R2(MuSig<G>),
}

impl<G: Group> MultiSig<G> {
    fn round_1(&mut self) {
        todo!()
    }
    fn round_2(&mut self) {
        todo!()
    }
    fn round_3(&mut self) {
        todo!()
    }
    fn sign(&mut self) -> Signature<G> {
        self.round_1();
        self.round_2();
        self.round_3();

        self.signature
    }
}

struct Signer<G: Group> {
    sk: G::Scalar,
    pk: G,
    r: G::Scalar,
}

struct MuSig<G: Group> {
    signers: &[Signer],
    message: &[u8],
    a_map: HashMap<Signer, G::Scalar>,
    commitment_map: HashMap<Signer, Commitment>,
    x: G,
    signature: Option<Signature<G>>,
}

struct Commitment<G: Group> {
    r_point: G,
    t: G::Scalar,
}

struct Signature<G: Group> {
    s: G::Scalar,
    r_point: G,
}

pub trait MusigGroup: Sized {
    type Scalar: PrimeField;

    // TODO: finish this
    fn verify(signature: (Self, Self::Scalar), pk_list: Vec<Self>, message: &str) -> bool;
}

// Domain separated hash functions for aggregation, commitment, and signature phases
fn hash_agg<T: Group + GroupEncoding>(pk_list: Vec<T>, pk: T) -> <T as Group>::Scalar {
    let mut input = vec!["agg".as_bytes()];
    for i in pk_list {
        let i_bytes = i.to_bytes();
        input.push(i_bytes.as_ref());
    }
    let pk_bytes = pk.to_bytes();
    input.push(pk_bytes.as_ref());
    return hash::<T>(input);
}

fn hash_com<T: Group + GroupEncoding>(r: T) -> <T as Group>::Scalar {
    let r_bytes = r.to_bytes();
    let input = vec!["com".as_bytes(), r_bytes.as_ref()];
    return hash::<T>(input);
}

fn hash_sig<T: Group + GroupEncoding>(x: T, r: T, m: &str) -> <T as Group>::Scalar {
    let x_bytes = x.to_bytes();
    let r_bytes = r.to_bytes();
    let input = vec![
        "sig".as_bytes(),
        x_bytes.as_ref(),
        r_bytes.as_ref(),
        m.as_bytes(),
    ];
    return hash::<T>(input);
}
impl<T: Group + GroupEncoding> MusigGroup for T {
    type Scalar = <Self as Group>::Scalar;

    //INCOMPLETE
    fn verify(signature: (Self, Self::Scalar), pk_list: Vec<T>, message: &str) -> bool {
        let (r, s) = signature;
        let mut x = Self::identity();
        for pk in pk_list {
            // TODO: make this work
            let a = hash_agg::<T>(pk_list, pk);
            x += pk * a;
        }

        let c = hash_sig::<T>(x, r, message);

        return Self::generator() == r + x * c;
    }
}
