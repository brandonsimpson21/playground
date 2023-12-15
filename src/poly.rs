use crate::error::PlaygroundError;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};

use ark_ec::{bls12::Bls12, pairing::Pairing};

use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    MontBackend, PrimeField as ArkFFPrimeField,
};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};

use ark_poly_commit::{
    challenge::ChallengeGenerator, marlin_pc::MarlinKZG10, Evaluations, LabeledCommitment,
    LabeledPolynomial, PolynomialCommitment, QuerySet,
};
use ark_std::test_rng;
use ark_test_curves::bls12_381::{Bls12_381, FrConfig};

pub type UniPoly381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
pub type SpongeBls312 = PoseidonSponge<<Bls12_381 as Pairing>::ScalarField>;
pub type PCS = MarlinKZG10<Bls12_381, UniPoly381, SpongeBls312>;
pub type ChallGenerator = ChallengeGenerator<<Bls12_381 as Pairing>::ScalarField, SpongeBls312>;

type LabeledPoly = LabeledPolynomial<
    ark_ff::Fp<MontBackend<FrConfig, 4>, 4>,
    DensePolynomial<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
>;

type PolyCommitmentScheme =
    ark_poly_commit::kzg10::UniversalParams<Bls12<ark_test_curves::bls12_381::Config>>;
type CommitKey =
    ark_poly_commit::marlin_pc::CommitterKey<Bls12<ark_test_curves::bls12_381::Config>>;
type VerifyKey = ark_poly_commit::marlin_pc::VerifierKey<Bls12<ark_test_curves::bls12_381::Config>>;
type Commitment = LabeledCommitment<
    ark_poly_commit::marlin_pc::Commitment<Bls12<ark_test_curves::bls12_381::Config>>,
>;
type Rands = ark_poly_commit::marlin_pc::Randomness<
    ark_ff::Fp<MontBackend<FrConfig, 4>, 4>,
    DensePolynomial<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
>;
type Proof = ark_poly_commit::kzg10::Proof<Bls12<ark_test_curves::bls12_381::Config>>;

#[derive(Clone)]
pub struct Poly {
    pub label: String,
    pub degree: usize,
    pub poly: LabeledPoly,
    ck: CommitKey,
    vk: VerifyKey,
}

impl std::fmt::Debug for Poly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poly")
            .field("degree", &self.degree)
            .field("poly", &self.poly)
            .finish()
    }
}

impl Default for Poly {
    fn default() -> Self {
        let degree = 12;
        let rng = &mut test_rng();
        // TODO REMOVE
        tracing::warn!("PCS SETUP SHOULD BE REMOVED!!!");
        let pp: PolyCommitmentScheme = PCS::setup(degree, None, rng).unwrap();
        let label = "default".to_string();
        let (ck, vk) = PCS::trim(&pp, degree, 2, Some(&[degree])).unwrap();
        let poly = LabeledPolynomial::new(
            label.clone(),
            UniPoly381::rand(degree, &mut test_rng()),
            Some(degree),
            Some(2),
        );
        Self {
            label,
            degree,
            poly,
            ck,
            vk,
        }
    }
}

impl Poly {
    pub fn new(
        degree: usize,
        label: &str,
        poly: LabeledPoly,
        ck: CommitKey,
        vk: VerifyKey,
    ) -> Self {
        Self {
            label: label.to_string(),
            degree,
            poly,
            ck,
            vk,
        }
    }

    #[inline(always)]
    pub fn eval(
        &self,
        point: &<Bls12_381 as Pairing>::ScalarField,
    ) -> <Bls12_381 as Pairing>::ScalarField {
        self.poly.evaluate(point)
    }

    #[inline(always)]
    pub fn commit(&self) -> (Vec<Commitment>, Vec<Rands>) {
        let rng = &mut test_rng();
        PCS::commit(&self.ck, [&self.poly], Some(rng)).unwrap()
    }

    pub fn proof_single(
        &self,
        sponge: PoseidonSponge<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        comms: &[Commitment],
        point: <Bls12_381 as Pairing>::ScalarField,
        rands: &[Rands],
    ) -> Result<Proof, PlaygroundError> {
        let mut sponge = sponge;
        let challenge_generator = ChallGenerator::new_univariate(&mut sponge);
        let proof = PCS::open(
            &self.ck,
            [&self.poly],
            comms,
            &point,
            &mut (challenge_generator.clone()),
            rands,
            None,
        );
        proof.map_err(|e| e.into())
    }

    pub fn proof_batched(
        &self,
        sponge: PoseidonSponge<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        query_set: QuerySet<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        comms: &[Commitment],
        rands: &[Rands],
    ) -> Result<Vec<Proof>, PlaygroundError> {
        let rng = &mut test_rng();
        let mut sponge = sponge;
        let challenge_generator = ChallGenerator::new_univariate(&mut sponge);

        let batch_proofs = PCS::batch_open(
            &self.ck,
            [&self.poly],
            comms,
            &query_set,
            &mut (challenge_generator.clone()),
            rands,
            Some(rng),
        );
        batch_proofs.map_err(|e| e.into())
    }

    pub fn check_single(
        &self,
        point: <Bls12_381 as Pairing>::ScalarField,
        sponge: PoseidonSponge<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        proof: Proof,
        comms: &[Commitment],
    ) -> Result<bool, PlaygroundError> {
        let rng = &mut test_rng();
        let mut sponge = sponge;
        let mut chall_gen = ChallGenerator::new_univariate(&mut sponge);
        PCS::check(
            &self.vk,
            comms,
            &point,
            [self.poly.evaluate(&point)],
            &proof,
            &mut (chall_gen),
            Some(rng),
        )
        .map_err(|e| e.into())
    }

    pub fn check_batched(
        &self,
        sponge: PoseidonSponge<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        proofs: &[Proof],
        comms: &[Commitment],
        query_set: &QuerySet<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        evals: Evaluations<
            ark_ff::Fp<MontBackend<FrConfig, 4>, 4>,
            ark_ff::Fp<MontBackend<FrConfig, 4>, 4>,
        >,
    ) -> Result<bool, PlaygroundError> {
        let rng = &mut test_rng();
        let mut sponge = sponge;
        let mut chall_gen = ChallGenerator::new_univariate(&mut sponge);
        PCS::batch_check(
            &self.vk,
            comms,
            query_set,
            &evals,
            &proofs.into(),
            &mut (chall_gen),
            rng,
        )
        .map_err(|e| e.into())
    }

    pub fn get_query_eval_set(
        &self,
        points: Vec<<Bls12_381 as Pairing>::ScalarField>,
    ) -> (
        QuerySet<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        Evaluations<
            ark_ff::Fp<MontBackend<FrConfig, 4>, 4>,
            ark_ff::Fp<MontBackend<FrConfig, 4>, 4>,
        >,
    ) {
        let mut query_set = QuerySet::new();
        let mut values = Evaluations::new();
        for (i, point) in points.iter().enumerate() {
            query_set.insert((self.label.clone(), (format!("{}", i), point.clone())));
            let value = self.poly.evaluate(&point);
            values.insert((self.label.clone(), point.clone()), value);
        }
        (query_set, values)
    }

    #[inline(always)]
    pub fn sha256_hash_to_field<B: AsRef<[u8]>, F: ark_ff::PrimeField>(
        &self,
        bytes: B,
        num_elements: usize,
    ) -> Vec<F> {
        let hasher =
            <DefaultFieldHasher<ark_crypto_primitives::crh::sha256::Sha256> as HashToField<F>>::new(
                self.label.as_bytes(),
            );

        hasher.hash_to_field(bytes.as_ref(), num_elements)
    }

    #[inline(always)]
    pub fn blake3_hash_to_field<B: AsRef<[u8]>, F: ark_ff::PrimeField>(
        &self,
        bytes: B,
        num_elements: usize,
    ) -> Vec<F> {
        let mut blake_hasher = blake3::Hasher::new();
        blake_hasher.update(self.label.as_bytes());
        blake_hasher.update(bytes.as_ref());
        let mut reader = blake_hasher.finalize_xof();
        let m = F::extension_degree() as usize;
        let mut output = Vec::with_capacity(num_elements);
        let mut base_prime_field_elems = Vec::with_capacity(m);
        let len_per_base_elem = F::MODULUS_BIT_SIZE as usize;
        let mut uniform_bytes = vec![0; len_per_base_elem * m * num_elements * m];
        reader.fill(&mut uniform_bytes);
        for i in (0..num_elements).into_iter() {
            base_prime_field_elems.clear();
            for j in (0..m).into_iter() {
                let elm_offset = len_per_base_elem * (j + i * m);
                let val = F::BasePrimeField::from_be_bytes_mod_order(
                    &uniform_bytes[elm_offset..][..len_per_base_elem],
                );
                base_prime_field_elems.push(val);
            }
            let f = F::from_base_prime_field_elems(&base_prime_field_elems).unwrap();
            output.push(f);
        }
        output
    }
}

pub fn test_sponge<F: ArkFFPrimeField>() -> PoseidonSponge<F> {
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 17;

    let mds = vec![
        vec![F::one(), F::zero(), F::one()],
        vec![F::one(), F::one(), F::zero()],
        vec![F::zero(), F::one(), F::one()],
    ];

    let mut v = Vec::new();
    let mut ark_rng = test_rng();

    for _ in 0..(full_rounds + partial_rounds) {
        let mut res = Vec::new();

        for _ in 0..3 {
            res.push(F::rand(&mut ark_rng));
        }
        v.push(res);
    }
    let config = PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, v, 2, 1);
    PoseidonSponge::new(&config)
}

#[cfg(test)]
mod testpoly {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn test_single_commitment() {
        let poly = Poly::default();
        let (comms, rands) = poly.commit();
        let sponge = test_sponge();
        let point = <Bls12_381 as Pairing>::ScalarField::rand(&mut test_rng());
        let proof = poly.proof_single(sponge.clone(), &*comms, point, &*rands);
        assert!(proof.is_ok());
        let proof = proof.unwrap();
        let check = poly.check_single(point, sponge.clone(), proof, &*comms);
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(check);
        let point2 = <Bls12_381 as Pairing>::ScalarField::rand(&mut test_rng());
        let check = poly.check_single(point2, sponge.clone(), proof, &*comms);
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(!check);
    }

    #[test]
    fn test_batch() {
        let poly = Poly::default();
        let (comms, rands) = poly.commit();
        let sponge = test_sponge();
        let points = vec![<Bls12_381 as Pairing>::ScalarField::rand(&mut test_rng()); 10];
        let (query_set, evals) = poly.get_query_eval_set(points.clone());
        let proofs = poly.proof_batched(sponge.clone(), query_set.clone(), &*comms, &*rands);
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap();
        let check = poly.check_batched(sponge.clone(), &*proofs, &*comms, &query_set, evals);
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(check);
    }

    #[test]
    fn test_sha_256_hash() {
        let poly = Poly::default();
        let (comms, rands) = poly.commit();
        let sponge = test_sponge();
        let points = poly.sha256_hash_to_field(b"hello, world", 10);
        let (query_set, evals) = poly.get_query_eval_set(points.clone());
        let proofs = poly.proof_batched(sponge.clone(), query_set.clone(), &*comms, &*rands);
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap();
        let check = poly.check_batched(sponge.clone(), &*proofs, &*comms, &query_set, evals);
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(check);
    }

    #[test]
    fn test_blake3_hash() {
        let poly = Poly::default();
        let (comms, rands) = poly.commit();
        let sponge = test_sponge();
        let points = poly.blake3_hash_to_field(b"hello, world", 10);
        let (query_set, evals) = poly.get_query_eval_set(points.clone());
        let proofs = poly.proof_batched(sponge.clone(), query_set.clone(), &*comms, &*rands);
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap();
        let check = poly.check_batched(sponge.clone(), &*proofs, &*comms, &query_set, evals);
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(check);
    }
}
