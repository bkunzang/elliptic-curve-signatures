use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::hash;
use elliptic_curve::{group::GroupEncoding, Field, Group, PrimeField};

// Signer
// MuSig
// Commitment
// Signature

// round_1 -> (a_map, x)
// round_2 -> bool
// round_3 -> Signature

#[derive(Debug, Clone)]
enum MultiSig<'a, G: Group + GroupEncoding> {
    R0(MuSig<'a, G>),
    R1(MuSig<'a, G>),
    R2(MuSig<'a, G>),
    R3(MuSig<'a, G>),
}

impl<'a, G: Group + GroupEncoding> MultiSig<'a, G>
where
    G: Hash,
    G::Scalar: Hash,
{
    fn round_1(&mut self) {
        match self {
            Self::R0(m) => {
                let all_pk = m.signers.iter().map(Signer::pk).collect::<Vec<_>>();
                // TODO: don't actually clone `all_pk` repeatedly.
                // hash it once, then incrementally hash the unique suffix.
                m.a_vec = m
                    .signers
                    .iter()
                    .map(|signer| Some(hash_agg(all_pk.clone(), signer.pk())))
                    .collect();

                m.x = m
                    .signers
                    .iter()
                    .zip(m.a_vec.iter())
                    .map(|(signer, a)| signer.pk() * a.expect("missing a"))
                    .sum();
            }
            _ => panic!("bro, can do no"),
        }
    }
    fn round_2(&mut self) {
        todo!()
    }
    fn round_3(&mut self) {
        match self {
            Self::R3(m) => {
                let r_point = m
                    .signers
                    .iter()
                    .fold(G::identity(), |acc, signer| acc + signer.r_point());

                let c = hash_sig(m.x, r_point, m.message);

                let s = m
                    .signers
                    .iter()
                    .enumerate()
                    .fold(G::Scalar::ZERO, |acc, (i, signer)| {
                        let a = m.a_vec[i].expect("a missing");
                        signer.s(c, a)
                    });

                m.signature = Some(Signature { s, r_point });
            }
            _ => panic!("no can do, bro"),
        }
    }
    fn sign(&mut self) -> Option<Signature<G>> {
        self.round_1();
        self.round_2();
        self.round_3();

        match self {
            Self::R3(m) => m.signature.clone(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct Signer<G: Group> {
    sk: G::Scalar,
    pk: G,
    r: G::Scalar,
}

impl<G: Group> Signer<G> {
    fn r_point(&self) -> G {
        G::generator() * self.r
    }

    fn s(&self, c: G::Scalar, a: G::Scalar) -> G::Scalar {
        self.r + c * a * self.sk
    }
    fn pk(&self) -> G {
        self.pk
    }
}

#[derive(Debug, Clone)]
struct MuSig<'a, G: Group> {
    signers: &'a [Signer<G>],
    message: &'a [u8],
    a_vec: Vec<Option<G::Scalar>>,
    commitment_vec: Vec<Option<Commitment<G>>>,
    x: G,
    signature: Option<Signature<G>>,
}

impl<'a, G: Group> MuSig<'a, G> {
    fn new(signers: &[Signer<G>]) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone)]
struct Commitment<G: Group> {
    r_point: G,
    t: G::Scalar,
}

#[derive(Debug, Clone)]
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
    todo!()
}
// fn hash_agg<T: Group + GroupEncoding>(pk_list: Vec<T>, pk: T) -> <T as Group>::Scalar {
//     let mut input = vec!["agg".as_bytes()];
//     for i in pk_list {
//         let i_bytes = i.to_bytes();
//         input.push(i_bytes.as_ref());
//     }
//     let pk_bytes = pk.to_bytes();
//     input.push(pk_bytes.as_ref());
//     return hash::<T>(input);
// }

fn hash_com<T: Group + GroupEncoding>(r: T) -> <T as Group>::Scalar {
    let r_bytes = r.to_bytes();
    let input = vec!["com".as_bytes(), r_bytes.as_ref()];
    return hash::<T>(input);
}

fn hash_sig<T: Group + GroupEncoding>(x: T, r: T, m: &[u8]) -> <T as Group>::Scalar {
    let x_bytes = x.to_bytes();
    let r_bytes = r.to_bytes();
    let input = vec!["sig".as_bytes(), x_bytes.as_ref(), r_bytes.as_ref(), m];
    return hash::<T>(input);
}
// impl<T: Group + GroupEncoding> MusigGroup for T {
//     type Scalar = <Self as Group>::Scalar;

//     //INCOMPLETE
//     fn verify(signature: (Self, Self::Scalar), pk_list: Vec<T>, message: &str) -> bool {
//         let (r, s) = signature;
//         let mut x = Self::identity();
//         for pk in pk_list {
//             // TODO: make this work
//             let a = hash_agg::<T>(pk_list, pk);
//             x += pk * a;
//         }

//         let c = hash_sig::<T>(x, r, message);

//         return Self::generator() == r + x * c;
//     }
// }
