use elliptic_curve::{group::GroupEncoding, Field, Group, generic_array::GenericArray};
use sha2::{Digest, Sha256};
use sha2::digest::generic_array::typenum::U32;
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

impl<'a, G: Group + GroupEncoding> From<&'a mut MuSig<'a, G>> for R0<'a, G> {
    fn from(m: &'a mut MuSig<'a, G>) -> Self {
        Self(m)
    }
}

impl<'a, G: Group + GroupEncoding> MuSig<'a, G> {
    fn sign(&'a mut self) -> Signature<G> {
        R0::from(self).sign().clone()
    }
}

impl<'a, G: Group + GroupEncoding> R0<'a, G> {
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

        //hash_agg(all_pk.clone(), signer.pk())
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
            .expect("missing signature")
    }
}

impl<'a, G: Group + GroupEncoding> R1<'a, G> {
    fn round_2(self) -> R2<'a, G> {
        let m: &mut _ = self.0;

        m.commitment_vec = m.signers.iter().map(|signer| signer.commit()).collect();
        m.opened_commitment_vec = m.signers.iter().map(|signer| signer.r_point()).collect();
        let verifier: bool = m
            .signers
            .iter()
            .map(|signer| signer.verify_all_commits(&m.opened_commitment_vec, &m.commitment_vec))
            .fold(true, |acc, ver| acc && ver);

        // TODO: Add an error type so that this can fail if `verifier == false`
        R2(m)
    }
}

impl<'a, G: Group + GroupEncoding> R2<'a, G> {
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
                acc + signer.s(c, a)
            });

        m.signature = Some(Signature { s, r_point });

        R3(m)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Signer<G: Group> {
    sk: G::Scalar,
    pk: G,
    r: G::Scalar,
}

impl<G: Group + GroupEncoding> Signer<G> {
    fn r_point(&self) -> G {
        G::generator() * self.r
    }

    fn s(&self, c: G::Scalar, a: G::Scalar) -> G::Scalar {
        self.r + c * a * self.sk
    }
    fn pk(&self) -> G {
        self.pk
    }

    fn commit(&self) -> G::Scalar {
        hash_com(self.r_point())
    }

    fn verify_commit(commitment: G::Scalar, r_point: G) -> bool {
        hash_com(r_point) == commitment
    }

    fn verify_all_commits(&self, r_point_vec: &Vec<G>, commit_vec: &Vec<G::Scalar>) -> bool {
        let verifier = commit_vec
            .iter()
            .zip(r_point_vec)
            .fold(true, |acc, (commitment, r_point)| {
                acc && Signer::<G>::verify_commit(*commitment, *r_point)
            });
        verifier
    }
}

#[derive(Debug, Clone)]
struct MuSig<'a, G: Group> {
    signers: &'a [Signer<G>],
    message: &'a [u8],
    a_vec: Vec<Option<G::Scalar>>,
    commitment_vec: Vec<G::Scalar>,
    opened_commitment_vec: Vec<G>,
    x: G,
    signature: Option<Signature<G>>,
}

impl<'a, G: Group> MuSig<'a, G> {
    fn new(signers: &'a [Signer<G>], message: &'a [u8]) -> Self {
        MuSig {
            signers: signers,
            message: message,
            a_vec: vec![None; signers.len()],
            commitment_vec: Vec::new(),
            opened_commitment_vec: Vec::new(),
            x: G::identity(),
            signature: None,
        }
    }
}

//#[derive(Debug, Clone)]
/* struct Commitment<G: Group> {
    r_point: G,
    t: G::Scalar,
}

impl<G: Group> Commitment<G> {
    fn open_commit(&self) -> G {
        self.r_point
    }

    fn commitment(&self) -> G::Scalar {
        self.t
    }
} */
#[derive(Debug, Clone)]
struct Signature<G: Group> {
    s: G::Scalar,
    r_point: G,
}

impl<G: Group> Signature<G> {
    fn s(&self) -> G::Scalar {
        self.s
    }

    fn r_point(&self) -> G {
        self.r_point
    }
}

fn verify<T: Group + GroupEncoding>(
    signature: Signature<T>,
    pk_list: Vec<T>,
    message: &[u8],
) -> bool {
    let s = signature.s();
    let r_point = signature.r_point();
    let a_vec: Vec<T::Scalar> = pk_list
        .clone()
        .iter()
        .map(|pk| hash_agg(pk_list.clone(), *pk))
        .collect();
    let x = a_vec
        .iter()
        .zip(pk_list)
        .fold(T::identity(), |acc, (a, pk)| acc + pk * a);
    let c = hash_sig(x, r_point, message);
    T::generator() * s == r_point + x * c
}

/* pub trait MusigGroup: Sized {
    type Scalar: PrimeField;

    // TODO: finish this
    fn verify(signature: (Self, Self::Scalar), pk_list: Vec<Self>, message: &str) -> bool;
} */

// Domain separated hash functions for aggregation, commitment, and signature phases
/* fn hash_agg_base<T: Group + GroupEncoding>(pk_list: Vec<T>) -> GenericArray<u8, U32> {
     let pk_bytes = pk_list.iter().map(|pk| pk.to_bytes()).collect();
     let mut hash = Sha256::new_with_prefix("agg");
     for byte in pk_bytes {
        hash.update(byte)
     }
     return hash.finalize()
}

fn hash_agg_final<T:Group + GroupEncoding>(base: GenericArray<u8, U32>, pk: T) -> GenericArray<> */

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

fn hash_agg<T: Group + GroupEncoding>(pk_list: Vec<T>, pk: T) -> <T as Group>::Scalar {
    let mut hash = Sha256::new_with_prefix("agg");
    let pk_list_bytes: Vec<<T as GroupEncoding>::Repr> =
        pk_list.iter().map(|pk| pk.to_bytes()).collect();
    for pk in pk_list_bytes {
        hash.update(pk);
    }
    hash.update(pk.to_bytes());
    let hash_scalar = hash_to_scalar::<T>(hash.finalize());
    return hash_scalar;
}

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

fn hash_to_scalar<T: Group>(hash: GenericArray<u8, U32>) -> T::Scalar {
    let mut scalar = <T::Scalar as Field>::ZERO;
    let scalar256 = <T::Scalar as From<u64>>::from(256);
    for byte in hash {
        scalar *= scalar256; // TODO: Maybe do this by doubling?
        scalar += <T::Scalar as From<u64>>::from(byte as u64)
    }
    scalar
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::ProjectivePoint;
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    #[test]
    fn musig_test_true() {
        for _ in 1..100 {
            musig_test_true_aux()
        }
    }

    #[test]
    fn musig_test_false() {
        for _ in 1..100 {
            musig_test_false_aux()
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

    fn generate_random_signer<T: Group + GroupEncoding>() -> Signer<T> {
        let rng1 = rand::thread_rng();
        let rng2 = rand::thread_rng();
        let sk = <T::Scalar as Field>::random(rng1);
        Signer {
            sk: sk,
            pk: T::generator() * sk,
            r: <T::Scalar as Field>::random(rng2),
        }
    }

    fn musig_test_true_aux() {
        let message_str = get_random_message(10);
        let message = message_str.as_bytes();
        let num_signers = rand::thread_rng().gen_range(5..20);
        let mut signers = Vec::new();
        for _ in 1..num_signers {
            signers.push(generate_random_signer::<ProjectivePoint>());
        }
        let pk_list = signers.iter().map(|signer| signer.pk()).collect();
        let mut musig = MuSig::<ProjectivePoint>::new(&signers[..], message);
        let signature = musig.sign();

        let verifier = verify(signature, pk_list, message);
        assert_eq!(verifier, true);
    }

    fn musig_test_false_aux() {
        let message_str = get_random_message(10);
        let message = message_str.as_bytes();
        let num_signers = rand::thread_rng().gen_range(5..20);
        let mut signers = Vec::new();
        for i in 1..num_signers {
            signers.push(generate_random_signer::<ProjectivePoint>());
        }
        let pk_list = signers.iter().map(|signer| signer.pk()).collect();
        let mut musig = MuSig::<ProjectivePoint>::new(&signers[..], message);
        let signature = musig.sign();

        let message_altered_str = get_random_message(11);
        let message_altered = message_altered_str.as_bytes();
        let verifier = verify(signature, pk_list, message_altered);
        assert_eq!(verifier, false);
    }

    /*
    fn verify_commit_test_aux() {
        let signers_number = rand::thread_rng().gen_range(1..15);
        let commitment_vec: Vec< = Vec::new();

    } */
}
