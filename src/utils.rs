use std::hash::Hash;

use crate::{error::PlaygroundError, poly::{Poly, test_sponge}};
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_ec::pairing::Pairing;
use ark_std::test_rng;
use ark_test_curves::bls12_381::{Bls12_381, FrConfig};
use salvo::prelude::*;
use tracing::{trace, field};
use ark_ff::{UniformRand, MontBackend, BigInt, PrimeField, field_hashers::{DefaultFieldHasher, HashToField}};
use sha3::{Digest, Sha3_256};


/// hash bytes to field 
/// EG.
/// ```rust
///     use ark_test_curves::bls12_381::Bls12_381;
///     use ark_ec::pairing::Pairing;
///     use ark_ff::PrimeField;
///     use utils::sha256_hash_to_field;
///     fn main(){
///         let bytes = b"hello world";
///         let point: <Bls12_381 as Pairing>::ScalarField = sha256_hash_to_field(bytes);
///     }
/// ```
#[inline(always)]
pub fn sha256_hash_to_field<B: AsRef<[u8]>, F: ark_ff::PrimeField>(bytes: B) -> F {
    let mut hasher = sha3::Sha3_256::default();
    hasher.update(bytes.as_ref());
    let bytes = hasher.finalize();
    F::from_be_bytes_mod_order(bytes.as_ref()) //TODO byte order
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<F>>::new();
    let field_elements: Vec<F> = hasher.hash_to_field(b"Hello, World!", 2);
    field_elements
}



#[cfg(test)]
mod test {
    use crate::error::PlaygroundError;

    use super::*;

    #[tokio::test]
    async fn test_sha256_hash_to_field() -> Result<(), PlaygroundError> {
        let bytes = b"hello world";
        let point: <Bls12_381 as Pairing>::ScalarField = sha256_hash_to_field(bytes);
        let poly = Poly::default();
        let (comms, rands) = poly.commit();
        let sponge = test_sponge();
        let proof = poly.proof_single(sponge.clone(), &*comms, point, &*rands)?;
        let check = poly.check_single(point, sponge.clone(), proof, &*comms);
        assert!(check.is_ok());
        let check = check.unwrap();
        assert!(check);
    
        Ok(())
    }
}
