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
    challenge::ChallengeGenerator,
    kzg10,
    marlin_pc::MarlinKZG10,
    marlin_pc::{self, CommitterKey, Randomness, VerifierKey},
    Evaluations, LabeledCommitment, LabeledPolynomial, PolynomialCommitment, QuerySet,
};
use ark_std::test_rng;
use ark_test_curves::bls12_381::{Bls12_381, FrConfig};

pub type PrimeScalarField = <Bls12_381 as Pairing>::ScalarField;
pub type PField = ark_ff::Fp<MontBackend<FrConfig, 4>, 4>;
pub type UniPoly381 = DensePolynomial<PrimeScalarField>;
pub type SpongeBls312 = PoseidonSponge<PrimeScalarField>;
pub type PCS = MarlinKZG10<Bls12_381, UniPoly381, SpongeBls312>;
pub type ChallGenerator = ChallengeGenerator<PrimeScalarField, SpongeBls312>;
pub type LabeledPoly = LabeledPolynomial<PField, DensePolynomial<PField>>;
pub type BLSPairingConfig = Bls12<ark_test_curves::bls12_381::Config>;
pub type PolyCommitmentScheme = kzg10::UniversalParams<BLSPairingConfig>;
pub type CommitKey = CommitterKey<BLSPairingConfig>;
pub type VerifyKey = VerifierKey<BLSPairingConfig>;
pub type Commitment = LabeledCommitment<marlin_pc::Commitment<BLSPairingConfig>>;
pub type Rands = Randomness<PField, DensePolynomial<PField>>;
pub type Proof = kzg10::Proof<BLSPairingConfig>;

#[derive(Clone)]
pub struct Poly {
    pub label: String,
    pub poly: LabeledPoly,
    pub pcs: PolyCommitmentScheme,
    ck: CommitKey,
    vk: VerifyKey,
}

impl std::fmt::Debug for Poly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poly")
            .field("degree", &self.degree())
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
        tracing::error!("PCS SETUP SHOULD BE REMOVED!!!");
        let pcs: PolyCommitmentScheme = PCS::setup(degree, None, rng).unwrap();
        let label = "default".to_string();
        let (ck, vk) = PCS::trim(&pcs, degree, 2, Some(&[degree])).unwrap();

        let poly = LabeledPolynomial::new(
            label.clone(),
            UniPoly381::rand(degree, &mut test_rng()),
            Some(degree),
            Some(2),
        );
        Self {
            label,
            poly,
            pcs,
            ck,
            vk,
        }
    }
}

impl Poly {
    pub fn new(
        label: &str,
        poly: LabeledPoly,
        pcs: PolyCommitmentScheme,
        ck: CommitKey,
        vk: VerifyKey,
    ) -> Self {
        Self {
            label: label.to_string(),
            poly,
            pcs,
            ck,
            vk,
        }
    }
    pub fn degree(&self) -> usize {
        self.poly.degree()
    }

    pub fn polynomial(&self) -> &UniPoly381 {
        self.poly.polynomial()
    }

    #[inline(always)]
    pub fn evaluate(&self, point: &PrimeScalarField) -> PrimeScalarField {
        self.poly.evaluate(point)
    }

    #[inline(always)]
    pub fn commit(&self) -> (Vec<Commitment>, Vec<Rands>) {
        let rng = &mut test_rng();
        PCS::commit(&self.ck, [&self.poly], Some(rng)).unwrap()
    }

    pub fn proof_single(
        &self,
        sponge: PoseidonSponge<PField>,
        comms: &[Commitment],
        point: PrimeScalarField,
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
        sponge: PoseidonSponge<PField>,
        query_set: QuerySet<PField>,
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
        point: PrimeScalarField,
        sponge: PoseidonSponge<PField>,
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
        sponge: PoseidonSponge<PField>,
        proofs: &[Proof],
        comms: &[Commitment],
        query_set: &QuerySet<PField>,
        evals: Evaluations<PField, PField>,
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
        points: Vec<PrimeScalarField>,
    ) -> (QuerySet<PField>, Evaluations<PField, PField>) {
        let mut query_set = QuerySet::new();
        let mut values = Evaluations::new();
        for (i, point) in points.iter().enumerate() {
            query_set.insert((self.label.clone(), (format!("{}", i), *point)));
            let value = self.poly.evaluate(point);
            values.insert((self.label.clone(), *point), value);
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
        for i in 0..num_elements {
            base_prime_field_elems.clear();
            for j in 0..m {
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

impl std::ops::Add for Poly {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let degree_bound = self.poly.degree_bound();
        let hiding_bound = self.poly.hiding_bound();
        let poly = self.poly.polynomial() + rhs.poly.polynomial();
        Self {
            label: self.label.clone(),
            poly: LabeledPolynomial::new(self.label.clone(), poly, degree_bound, hiding_bound),
            pcs: self.pcs,
            ck: self.ck,
            vk: self.vk,
        }
    }
}

impl std::ops::Mul for Poly {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let degree_bound = self.poly.degree_bound();
        let hiding_bound = self.poly.hiding_bound();
        let poly = self.poly.polynomial() * rhs.poly.polynomial();
        Self {
            label: self.label.clone(),
            poly: LabeledPolynomial::new(self.label.clone(), poly, degree_bound, hiding_bound),
            pcs: self.pcs,
            ck: self.ck,
            vk: self.vk,
        }
    }
}

impl std::ops::Sub for Poly {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let degree_bound = self.poly.degree_bound();
        let hiding_bound = self.poly.hiding_bound();
        let poly = self.poly.polynomial() - rhs.poly.polynomial();
        Self {
            label: self.label.clone(),
            poly: LabeledPolynomial::new(self.label.clone(), poly, degree_bound, hiding_bound),
            pcs: self.pcs,
            ck: self.ck,
            vk: self.vk,
        }
    }
}

impl std::ops::Div for Poly {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let degree_bound = self.poly.degree_bound();
        let hiding_bound = self.poly.hiding_bound();
        let poly = self.poly.polynomial() / rhs.poly.polynomial();
        Self {
            label: self.label.clone(),
            poly: LabeledPolynomial::new(self.label.clone(), poly, degree_bound, hiding_bound),
            pcs: self.pcs,
            ck: self.ck,
            vk: self.vk,
        }
    }
}

#[cfg(test)]
mod testpoly {
    use super::*;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSpongeState;
    use ark_ff::UniformRand;

    #[test]
    fn test_single_commitment() {
        let poly = Poly::default();
        let (comms, rands) = poly.commit();
        let sponge = test_sponge();
        let point = PrimeScalarField::rand(&mut test_rng());
        let proof = poly.proof_single(sponge.clone(), &*comms, point, &*rands);
        assert!(proof.is_ok());
        let proof = proof.unwrap();
        let check = poly.check_single(point, sponge.clone(), proof, &*comms);
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(check);
        let point2 = PrimeScalarField::rand(&mut test_rng());
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
        let points = vec![PrimeScalarField::rand(&mut test_rng()); 10];
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

    #[test]
    fn test_poly(){
        let poly = Poly::default();
        let (comms, rands) = poly.commit();
        println!("comms: {:?}", comms.len());

    }
}
