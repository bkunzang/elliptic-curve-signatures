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

struct R0<'a, G: Group + GroupEncoding>(&'a mut MuSig<'a, G>);
struct R1<'a, G: Group + GroupEncoding>(&'a mut MuSig<'a, G>);
struct R2<'a, G: Group + GroupEncoding>(&'a mut MuSig<'a, G>);
struct R3<'a, G: Group + GroupEncoding>(&'a mut MuSig<'a, G>);

impl<'a, G: Group + GroupEncoding> From<&'a mut MuSig<'a, G>> for R0<'a, G>
where
    G: Hash,
    G::Scalar: Hash,
{
    fn from(m: &'a mut MuSig<'a, G>) -> Self {
        Self(m)
    }
}

impl<'a, G: Group + GroupEncoding> MuSig<'a, G>
where
    G: Hash,
    G::Scalar: Hash,
{
    fn sign(&'a mut self) -> Signature<G> {
        R0::from(self).sign().clone()
    }
}

impl<'a, G: Group + GroupEncoding> R0<'a, G>
where
    G: Hash,
    G::Scalar: Hash,
{
    fn round_1(self) -> R1<'a, G> {
        let m: &mut _ = self.0;

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

        R1(m)
    }

    fn sign(self) -> &'a Signature<G> {
        self.round_1()
            .round_2()
            .round_3()
            .0
            .signature
            .as_ref()
            .expect("missing siganture")
    }
}

impl<'a, G: Group + GroupEncoding> R1<'a, G>
where
    G: Hash,
    G::Scalar: Hash,
{
    fn round_2(self) -> R2<'a, G> {
        let m: &mut _ = self.0;

        todo!("round_2");

        R2(m)
    }
}

impl<'a, G: Group + GroupEncoding> R2<'a, G>
where
    G: Hash,
    G::Scalar: Hash,
{
    fn round_3(self) -> R3<'a, G> {
        let m: &mut _ = self.0;

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

        R3(m)
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
