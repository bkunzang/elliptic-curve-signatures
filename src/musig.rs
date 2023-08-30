use elliptic_curve::{generic_array::GenericArray, group::GroupEncoding, Field, Group};
use sha2::digest::generic_array::typenum::U32;
use sha2::{Digest, Sha256};
// Signer
// MuSig
// Signature

// round_1 -> (a_map, x)
// round_2 -> bool
// round_3 -> Signature

// Type state encode state of signature scheme; it is impossible to complete a signature round without all previous required rounds being completed.

/// Initial signature state
struct R0<'a, G: Group + GroupEncoding>(&'a mut MuSig<'a, G>);
/// State after completing round 1 of the signature process
struct R1<'a, G: Group + GroupEncoding>(&'a mut MuSig<'a, G>);
/// State after completing round 2 of the signature process
struct R2<'a, G: Group + GroupEncoding>(&'a mut MuSig<'a, G>);
/// State after completing round 3 of the signature process
struct R3<'a, G: Group + GroupEncoding>(&'a mut MuSig<'a, G>);



impl<'a, G: Group + GroupEncoding> From<&'a mut MuSig<'a, G>> for R0<'a, G> {
    /// Create R0 state from initial multi sig
    fn from(m: &'a mut MuSig<'a, G>) -> Self {
        Self(m)
    }
}

impl<'a, G: Group + GroupEncoding> MuSig<'a, G> {
    /// Complete all stages of signing from intial setup
    fn sign(&'a mut self) -> Signature<G> {
        R0::from(self).sign().clone()
    }
}

impl<'a, G: Group + GroupEncoding> R0<'a, G> {
    /// Round 1: Aggregate public keys, create 'a' for each signer by hashing all public keys plus each signer's individual public key and create aggregated public key
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

    /// Run all rounds of signing and create a signature given an initial multi sig.
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
    /// Round 2: Each signer randomly generates r, a scalar, and creates R = r * generator. They compute hash_com(R) and publish this commitment. Then, all signers publicize their R and verify all commitments.
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
        if verifier == true {
            return R2(m);
        } else {
            panic!()
        }
    }
}

impl<'a, G: Group + GroupEncoding> R2<'a, G> {
    /// Round 3: Create collective R and create signature
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
/// Represents a signer with a secret key, public key, and randomly generated value r
struct Signer<G: Group> {
    sk: G::Scalar,
    pk: G,
    r: G::Scalar,
}

impl<G: Group + GroupEncoding> Signer<G> {
    /// creates the point R = generator * r
    fn r_point(&self) -> G {
        G::generator() * self.r
    }

    /// Creates the signer's contribution to the collective signature: r + c * a * sk
    fn s(&self, c: G::Scalar, a: G::Scalar) -> G::Scalar {
        self.r + c * a * self.sk
    }

    /// Returns the signer's public key
    fn pk(&self) -> G {
        self.pk
    }

    /// Returns hash_com of the signer's R point
    fn commit(&self) -> G::Scalar {
        hash_com(self.r_point())
    }

    /// Verify a commitment to a randomly generated point like one produced by the commit function
    fn verify_commit(commitment: G::Scalar, r_point: G) -> bool {
        hash_com(r_point) == commitment
    }

    /// Verify commitmentss from all other signers
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

/// Represents a signature process with signers, a message, a vector of 'a' values, commitments, opened commitments, a collective public key, and a signature.
struct MuSig<'a, G: Group> {
    signers: &'a [Signer<G>],
    message: &'a [u8],
    a_vec: Vec<Option<G::Scalar>>,
    commitment_vec: Vec<G::Scalar>,
    opened_commitment_vec: Vec<G>,

    /// Collective public key
    x: G,
    signature: Option<Signature<G>>,
}

impl<'a, G: Group> MuSig<'a, G> {
    /// Create new signature process with signers and a message and no data in the other fields
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

#[derive(Debug, Clone)]

/// Represents a signature with s and R
struct Signature<G: Group> {
    s: G::Scalar,
    r_point: G,
}

impl<G: Group> Signature<G> {

    /// Returns the s value of a signature
    fn s(&self) -> G::Scalar {
        self.s
    }

    /// Returns the R value of a signature
    fn r_point(&self) -> G {
        self.r_point
    }
}

/// Verify a signature given the message and a list of public keys used in signing
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

// Domain separated hash functions for aggregation, commitment, and signature phases

/// Base hash function that takes in inputs and returns a scalar using Sha256
fn hash<T: Group>(inputs: Vec<&[u8]>) -> T::Scalar {
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


/// Hash agg: Takes in a list of public keys and an individual's public key and hashes them prefixed with "agg"
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

/// Creates a commitment by hashing a value prefixed with "com"
fn hash_com<T: Group + GroupEncoding>(r: T) -> <T as Group>::Scalar {
    let r_bytes = r.to_bytes();
    let input = vec!["com".as_bytes(), r_bytes.as_ref()];
    return hash::<T>(input);
}

/// Hashes a collective public key, a collective R point, and a message prefixed with "sig"
fn hash_sig<T: Group + GroupEncoding>(x: T, r: T, m: &[u8]) -> <T as Group>::Scalar {
    let x_bytes = x.to_bytes();
    let r_bytes = r.to_bytes();
    let input = vec!["sig".as_bytes(), x_bytes.as_ref(), r_bytes.as_ref(), m];
    return hash::<T>(input);
}

/// Converts the outputs of a hash function (GenericArray of bytes) to a scalar
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

    /// Generate random string for testing
    fn get_random_message(length: usize) -> String {
        let message: Vec<char> = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        let message2 = message.into_iter().collect::<String>();
        message2
    }

    /// Generate random signer for testing
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
    
    /// Test that a signature verifies when it its message is passed intact through the verifier
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


    /// Test that a signature fails to verify when its message is altered
    fn musig_test_false_aux() {
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

        let message_altered_str = get_random_message(11);
        let message_altered = message_altered_str.as_bytes();
        let verifier = verify(signature, pk_list, message_altered);
        assert_eq!(verifier, false);
    }
}
