//! Sending utility functions.
use crate::utils::common::{NonEmptyArray, OutPoint, TransactionSharedSecret, ecdh_multiply};
use crate::{Error, Result};
use secp256k1::constants::SECRET_KEY_SIZE;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};

use super::hash::calculate_input_hash;

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

/// Represents the sum of all eligible input private keys of a transaction, multiplied with the input hash.
#[derive(Clone, Copy, Debug)]
pub struct PartialSecret(pub(crate) SecretKey);

impl PartialSecret {
    /// Re-construct the partial secret from the inner bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(Self(SecretKey::from_slice(data)?))
    }

    /// Returns the inner bytes of the partial secret
    pub fn secret_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.0.secret_bytes()
    }
}

/// Calculate the partial secret that is needed for generating the recipient pubkeys.
///
/// # Arguments
///
/// * `input_keys` - A reference to a list of tuples, each tuple containing a [SecretKey] and [bool]. The [SecretKey] is the private key used in the input, and the [bool] indicates whether this was from a taproot address.
/// * `outpoints_data` - The prevout outpoints used as input for this transaction. Note that the txid is given in [String] format, which is displayed in reverse order from the inner byte array.
///
/// # Returns
///
/// This function returns the partial secret, which represents the sum of all (eligible) input keys multiplied with the input hash.
///
/// # Errors
///
/// This function will error if:
///
/// * The input keys array is of length zero, or the summing results in an invalid key.
/// * The outpoints_data is of length zero, or invalid.
pub fn calculate_partial_secret(
    input_keys: &[(SecretKey, bool)],
    outpoints_data: &[OutPoint],
) -> Result<PartialSecret> {
    let a_sum = get_a_sum_secret_keys(input_keys)?;

    let secp = Secp256k1::signing_only();
    let A_sum = a_sum.public_key(&secp);

    let outpoints = NonEmptyArray::new(outpoints_data)?;
    let input_hash = calculate_input_hash(outpoints.min(), A_sum);

    Ok(PartialSecret(a_sum.mul_tweak(&input_hash)?))
}

/// Calculate the shared secret of a transaction.
///
/// Since [generate_recipient_pubkeys](crate::sending::generate_recipient_pubkeys) calls this function internally, it is not needed for the default sending flow.
///
/// # Arguments
///
/// * `B_scan` - The scan public key used by the wallet.
/// * `partial_secret` - the sum of all (eligible) input keys multiplied with the input hash, see [calculate_partial_secret].
///
/// # Returns
///
/// This function returns the shared secret unique to this recipient and input keys. This shared secret can be used to generate output keys for the recipient.
pub fn calculate_ecdh_shared_secret(
    B_scan: &PublicKey,
    partial_secret: &PartialSecret,
) -> TransactionSharedSecret {
    TransactionSharedSecret::from_sender_ecdh(
        ecdh_multiply(B_scan, &partial_secret.0).expect("guaranteed to be a point on the curve"),
        *B_scan,
    )
}

fn get_a_sum_secret_keys(input: &[(SecretKey, bool)]) -> Result<SecretKey> {
    if input.is_empty() {
        return Err(Error::GenericError("No input provided".to_owned()));
    }

    let secp = Secp256k1::new();

    let normalized: Vec<NormalizedSecretKey> = input
        .iter()
        .map(|(key, is_taproot)| NormalizedSecretKey::new(&secp, *key, *is_taproot))
        .collect();

    let (head, tail) = normalized.split_first().expect("input is non-empty");

    tail.iter()
        .try_fold(*head.as_inner(), |acc, item| {
            acc.add_tweak(&(*item.as_inner()).into())
        })
        .map_err(Error::from)
}
