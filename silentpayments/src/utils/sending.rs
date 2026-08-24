//! Sending utility functions.
//!
//! The typical flow for a single signer is:
//!
//! 1. Normalize input private keys with [`NormalizedSecretKey`].
//! 2. Create a [`GlobalSenderEcdhShare`] (single spender) or [`PartialSenderEcdhShare`]s (per input - collaborative transaction).
//! 3. Verify BIP374 DLEQ proofs with [`PartialSenderEcdhShare::verify_dleq_proof`] /
//!    [`GlobalSenderEcdhShare::verify_dleq_proof`].
//! 4. Convert to a [`TransactionSharedSecret`](crate::TransactionSharedSecret), which applies the
//!    BIP352 input hash, and pass to [`generate_recipient_pubkeys`](crate::sending::generate_recipient_pubkeys).

use crate::utils::common::{NonEmptyArray, ecdh_multiply};
use crate::{Error, Result};
use rust_dleq::{DleqProof, generate_dleq_proof, verify_dleq_proof};
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, Verification};

/// Guarantees that the secret key produces an even x-only public key when the spent output is taproot,
/// by negating the secret key if necessary.
#[derive(Debug, Clone)]
pub struct NormalizedSecretKey(SecretKey);

impl NormalizedSecretKey {
    pub fn new<C: Signing>(secp: &Secp256k1<C>, secret_key: SecretKey, is_taproot: bool) -> Self {
        let (_, parity) = secret_key.x_only_public_key(secp);

        if is_taproot && parity == secp256k1::Parity::Odd {
            return Self(secret_key.negate());
        }

        Self(secret_key)
    }

    pub fn as_inner(&self) -> &SecretKey {
        &self.0
    }

    pub fn into_inner(self) -> SecretKey {
        self.0
    }
}

impl<'a> NonEmptyArray<'a, NormalizedSecretKey> {
    pub fn sum_keys(&self) -> Result<SecretKey> {
        let (head, tail) = self.as_inner().split_first().expect("Is non-empty");
        tail.iter()
            .try_fold(*head.as_inner(), |acc, item| {
                acc.add_tweak(&(*item.as_inner()).into())
            })
            .map_err(Error::from)
    }
}

/// ECDH share for a single eligible input: `a_i * B_scan` (before input hash).
///
/// Used in multi-signer flows where each party contributes one input.
/// Combine hashed partial shares into a [`TransactionSharedSecret`](crate::TransactionSharedSecret) via
/// [`TransactionSharedSecret::new_from_partial_shares`](crate::TransactionSharedSecret::new_from_partial_shares).
pub struct PartialSenderEcdhShare {
    recipient_scan_key: PublicKey,
    input_vin: usize,
    ecdh_shared_secret: PublicKey,
    dleq_proof: DleqProof,
}

impl PartialSenderEcdhShare {
    pub fn new<C: Signing + Verification>(
        secp: &Secp256k1<C>,
        recipient_scan_key: PublicKey,
        input_vin: usize,
        private_key: &NormalizedSecretKey,
        aux_rand: &[u8; 32],
    ) -> Result<Self> {
        let shared_secret = ecdh_multiply(&recipient_scan_key, private_key.as_inner())?;
        let proof = generate_dleq_proof(
            secp,
            private_key.as_inner(),
            &recipient_scan_key,
            aux_rand,
            None,
        )?;
        Ok(Self {
            recipient_scan_key,
            input_vin,
            ecdh_shared_secret: shared_secret,
            dleq_proof: proof,
        })
    }

    pub fn new_unchecked(
        recipient_scan_key: PublicKey,
        input_vin: usize,
        ecdh_shared_secret: PublicKey,
        dleq_proof: DleqProof,
    ) -> Self {
        Self {
            recipient_scan_key,
            input_vin,
            ecdh_shared_secret,
            dleq_proof,
        }
    }

    pub fn recipient_scan_key(&self) -> &PublicKey {
        &self.recipient_scan_key
    }

    pub fn input_vin(&self) -> usize {
        self.input_vin
    }

    pub fn as_ecdh_shared_secret(&self) -> &PublicKey {
        &self.ecdh_shared_secret
    }

    pub fn dleq_proof(&self) -> &DleqProof {
        &self.dleq_proof
    }

    pub fn verify_dleq_proof<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        input_pubkey: &PublicKey,
    ) -> Result<()> {
        let is_valid = verify_dleq_proof(
            secp,
            input_pubkey,
            &self.recipient_scan_key,
            &self.ecdh_shared_secret,
            &self.dleq_proof,
            None,
        )
        .map_err(Error::from)?;
        if !is_valid {
            return Err(Error::GenericError("Invalid DLEQ proof".to_owned()));
        }
        Ok(())
    }
}

/// ECDH share for all eligible inputs combined.
///
/// Built by summing private keys first ([`Self::new_from_summed_keys`]).
/// DLEQ proofs are generated at construction time and verified before use.
pub struct GlobalSenderEcdhShare {
    recipient_scan_key: PublicKey,
    ecdh_shared_secret: PublicKey,
    dleq_proof: DleqProof,
}

impl GlobalSenderEcdhShare {
    pub fn new_from_summed_keys<C: Signing + Verification>(
        secp: &Secp256k1<C>,
        recipient_scan_key: PublicKey,
        summed_keys: NonEmptyArray<NormalizedSecretKey>,
        aux_rand: &[u8; 32],
    ) -> Result<Self> {
        let secret_key = summed_keys.sum_keys()?;
        let shared_secret = ecdh_multiply(&recipient_scan_key, &secret_key)?;
        let proof = generate_dleq_proof(secp, &secret_key, &recipient_scan_key, aux_rand, None)?;
        Ok(Self {
            recipient_scan_key,
            ecdh_shared_secret: shared_secret,
            dleq_proof: proof,
        })
    }

    pub fn new_unchecked(
        recipient_scan_key: PublicKey,
        ecdh_shared_secret: PublicKey,
        dleq_proof: DleqProof,
    ) -> Self {
        Self {
            recipient_scan_key,
            ecdh_shared_secret,
            dleq_proof,
        }
    }

    /// Verify the DLEQ proof against the sum of eligible input public keys.
    pub fn verify_dleq_proof<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        input_pubkeys: NonEmptyArray<&PublicKey>,
    ) -> Result<()> {
        let summed_input_pubkey = PublicKey::combine_keys(input_pubkeys.as_inner())?;
        let is_valid = verify_dleq_proof(
            secp,
            &summed_input_pubkey,
            &self.recipient_scan_key,
            &self.ecdh_shared_secret,
            &self.dleq_proof,
            None,
        )
        .map_err(Error::from)?;
        if !is_valid {
            return Err(Error::GenericError("Invalid DLEQ proof".to_owned()));
        }
        Ok(())
    }

    pub fn recipient_scan_key(&self) -> &PublicKey {
        &self.recipient_scan_key
    }

    pub fn as_ecdh_shared_secret(&self) -> &PublicKey {
        &self.ecdh_shared_secret
    }

    pub fn dleq_proof(&self) -> &DleqProof {
        &self.dleq_proof
    }

    pub fn into_ecdh_shared_secret(self) -> PublicKey {
        self.ecdh_shared_secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    use std::str::FromStr;

    #[test]
    fn global_share_dleq_roundtrip() {
        let secp = Secp256k1::new();
        let private_key =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let scan_priv =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let recipient_scan_key = PublicKey::from_secret_key(&secp, &scan_priv);
        let summed_input_pubkey = PublicKey::from_secret_key(&secp, &private_key);
        let aux_rand = [3u8; 32];

        let global_share = GlobalSenderEcdhShare::new_from_summed_keys(
            &secp,
            recipient_scan_key,
            NonEmptyArray::new(&[NormalizedSecretKey::new(&secp, private_key, false)]).unwrap(),
            &aux_rand,
        )
        .unwrap();

        global_share
            .verify_dleq_proof(&secp, NonEmptyArray::new(&[&summed_input_pubkey]).unwrap())
            .unwrap();
    }

    #[test]
    fn partial_share_dleq_roundtrip() {
        let secp = Secp256k1::new();
        let private_key =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();
        let scan_priv =
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000004")
                .unwrap();
        let recipient_scan_key = PublicKey::from_secret_key(&secp, &scan_priv);
        let input_pubkey = PublicKey::from_secret_key(&secp, &private_key);
        let normalized = NormalizedSecretKey::new(&secp, private_key, false);
        let aux_rand = [5u8; 32];

        let partial =
            PartialSenderEcdhShare::new(&secp, recipient_scan_key, 0, &normalized, &aux_rand)
                .unwrap();

        partial.verify_dleq_proof(&secp, &input_pubkey).unwrap();
    }
}
