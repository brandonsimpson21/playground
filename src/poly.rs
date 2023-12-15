use crate::error::PlaygroundError;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge
};

use ark_ec::{bls12::Bls12,pairing::Pairing};

use ark_ff::{MontBackend, PrimeField as ArkFFPrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, };

use ark_poly_commit::{
    LabeledCommitment,
    challenge::ChallengeGenerator, marlin_pc::MarlinKZG10, Evaluations, LabeledPolynomial,
    PolynomialCommitment, QuerySet,
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
        let pp = PCS::setup(degree, None, rng).unwrap();
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

    pub fn commit(&self) -> (Vec<Commitment>, Vec<Rands>) {
        let rng = &mut test_rng();
        PCS::commit(&self.ck, [&self.poly], Some(rng)).unwrap()
    }

    pub fn proof_single(
        &self,
        sponge: PoseidonSponge<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        comms: Vec<Commitment>,
        point: <Bls12_381 as Pairing>::ScalarField,
        rands: Vec<Rands>,
    ) -> Result<Proof, PlaygroundError> {
        let mut sponge = sponge;
        let challenge_generator = ChallGenerator::new_univariate(&mut sponge);
        let proof = PCS::open(
            &self.ck,
            [&self.poly],
            &comms,
            &point,
            &mut (challenge_generator.clone()),
            &rands,
            None,
        );
        proof.map_err(|e| e.into())
    }
    pub fn proof_batched(
        &self,
        sponge: PoseidonSponge<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        query_set: QuerySet<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        comms: Vec<Commitment>,
        rands: Vec<Rands>,
    ) -> Result<Vec<Proof>, PlaygroundError> {
        let rng = &mut test_rng();
        let mut sponge = sponge;
        let challenge_generator = ChallGenerator::new_univariate(&mut sponge);

        let batch_proofs = PCS::batch_open(
            &self.ck,
            [&self.poly],
            &comms,
            &query_set,
            &mut (challenge_generator.clone()),
            &rands,
            Some(rng),
        );
        batch_proofs.map_err(|e| e.into())
    }

    pub fn check_single(
        &self,
        point: <Bls12_381 as Pairing>::ScalarField,
        sponge: PoseidonSponge<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        proof: Proof,
        comms: Vec<Commitment>,
    ) -> Result<bool, PlaygroundError> {
        let rng = &mut test_rng();
        let mut sponge = sponge;
        let mut chall_gen = ChallGenerator::new_univariate(&mut sponge);
        PCS::check(
            &self.vk,
            &comms,
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
        chall_gen: ChallGenerator,
        proofs: Vec<Proof>,
        comms: Vec<Commitment>,
        query_set: QuerySet<ark_ff::Fp<MontBackend<FrConfig, 4>, 4>>,
        evals: Evaluations<
            ark_ff::Fp<MontBackend<FrConfig, 4>, 4>,
            ark_ff::Fp<MontBackend<FrConfig, 4>, 4>,
        >,
    ) -> Result<bool, PlaygroundError> {
        let rng = &mut test_rng();
        let mut chall_gen = chall_gen;
        PCS::batch_check(
            &self.vk,
            &comms,
            &query_set,
            &evals,
            &proofs,
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
    fn test_poly() {
        let poly = Poly::default();
        let (comms, rands) = poly.commit();
        let sponge = test_sponge();
        let point = <Bls12_381 as Pairing>::ScalarField::rand(&mut test_rng());
        let proof = poly.proof_single(sponge.clone(), comms.clone(), point, rands.clone());
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        let check = poly.check_single(point, sponge.clone(), proof, comms.clone());
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(check);

        let point2 = <Bls12_381 as Pairing>::ScalarField::rand(&mut test_rng());
        let check = poly.check_single(point2, sponge.clone(), proof, comms.clone());
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(!check);

    }
}
