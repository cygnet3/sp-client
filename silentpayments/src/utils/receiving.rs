//! Receiving utility functions.
use crate::{
    Error, Result,
    utils::{
        common::TransactionInputs,
        hash::calculate_input_hash,
        script::{is_p2pkh, is_p2sh, is_p2wpkh},
    },
};

pub use crate::utils::script::{is_eligible, is_p2tr};
use bitcoin_hashes::{Hash, hash160};
use secp256k1::PublicKey;
use secp256k1::{Parity::Even, Secp256k1, Verification, XOnlyPublicKey};

use super::{
    COMPRESSED_PUBKEY_SIZE, NUMS_H, OP_PUSHBYTES_1, OP_PUSHBYTES_75, OP_PUSHDATA1, OP_PUSHDATA2,
    OP_PUSHDATA4, TAPROOT_ANNEX_PREFIX,
};

/// Returns the last data push in a push-only script, or `None` if malformed.
fn last_push(script: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    let mut last: Option<&[u8]> = None;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let (extra_len_bytes, data_len): (usize, usize) = match op {
            OP_PUSHBYTES_1..=OP_PUSHBYTES_75 => (0, op as usize),
            OP_PUSHDATA1 => (1, *script.get(i)? as usize),
            OP_PUSHDATA2 => {
                let lo = *script.get(i)? as usize;
                let hi = *script.get(i + 1)? as usize;
                (2, lo | (hi << 8))
            }
            OP_PUSHDATA4 => {
                let b0 = *script.get(i)? as usize;
                let b1 = *script.get(i + 1)? as usize;
                let b2 = *script.get(i + 2)? as usize;
                let b3 = *script.get(i + 3)? as usize;
                (4, b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
            }
            _ => return None,
        };
        i += extra_len_bytes;
        last = Some(script.get(i..i + data_len)?);
        i += data_len;
    }
    last
}

/// Parse a compressed witness pubkey and verify it matches the expected hash160.
fn witness_compressed_pubkey(
    witness_last: &[u8],
    expected_hash: &[u8],
) -> Result<Option<PublicKey>> {
    if witness_last.len() != COMPRESSED_PUBKEY_SIZE {
        return Ok(None);
    }
    let pubkey = match PublicKey::from_slice(witness_last) {
        Ok(pk) => pk,
        Err(_) => return Ok(None),
    };
    if hash160::Hash::hash(witness_last).to_byte_array() != expected_hash {
        return Ok(None);
    }
    Ok(Some(pubkey))
}

/// Public tweak data for a transaction: `input_hash * sum(eligible input pubkeys)`.
///
/// Indexing servers can publish this value so recipients can derive a
/// [`TransactionSharedSecret`](crate::TransactionSharedSecret) locally without revealing their scan private key.
pub struct PublicTweakData(PublicKey);

impl PublicTweakData {
    /// Construct tweak data from a value obtained from a trusted external source.
    ///
    /// Prefer [`Self::new`] when computing from chain data directly.
    pub fn new_unchecked(tweak_data: PublicKey) -> Self {
        Self(tweak_data)
    }

    /// Calculate the tweak data of a transaction: `input_hash * sum(eligible input pubkeys)`.
    ///
    /// Uses the same eligible-input rules as sender-side shared secret derivation. Combine with
    /// [`TransactionSharedSecret::new_from_public_tweak_data`](crate::TransactionSharedSecret::new_from_public_tweak_data)
    /// to obtain the shared secret used by [`Receiver::scan_transaction`](crate::receiving::Receiver::scan_transaction).
    ///
    /// # Arguments
    ///
    /// * `inputs` - Parallel outpoints, script pubkeys and extracted pubkeys for every vin.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// * `inputs` is empty.
    /// * No eligible input pubkeys could be extracted.
    /// * Elliptic curve computation results in an invalid public key.
    pub fn new<C: Verification>(secp: &Secp256k1<C>, inputs: &TransactionInputs) -> Result<Self> {
        let summed_pubkeys = inputs.eligible_pubkeys_sum()?;
        let input_hash = calculate_input_hash(inputs.min_outpoint(), summed_pubkeys);
        Ok(Self(summed_pubkeys.mul_tweak(secp, &input_hash)?))
    }

    pub fn as_inner(&self) -> &PublicKey {
        &self.0
    }
}

/// Get the public keys from a set of input data.
///
/// # Arguments
///
/// * `script_sig` - The script signature as a byte array.
/// * `txinwitness` - The witness data.
/// * `script_pub_key` - The scriptpubkey from the output spent. This requires looking up the previous output.
///
/// # Returns
///
/// If no errors occur, this function will optionally return a [PublicKey] if this input is silent payment-eligible.
///
/// # Errors
///
/// This function will error if:
///
/// * The provided Vin data is incorrect.
pub fn get_pubkey_from_input(
    script_sig: &[u8],
    txinwitness: &[Vec<u8>],
    script_pub_key: &[u8],
) -> Result<Option<PublicKey>> {
    if is_p2pkh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (true, false) => {
                let spk_hash = &script_pub_key[3..23];
                for i in (COMPRESSED_PUBKEY_SIZE..=script_sig.len()).rev() {
                    if let Some(pubkey_bytes) = script_sig.get(i - COMPRESSED_PUBKEY_SIZE..i) {
                        let pubkey_hash = hash160::Hash::hash(pubkey_bytes);
                        if pubkey_hash.to_byte_array() == spk_hash {
                            return Ok(Some(PublicKey::from_slice(pubkey_bytes)?));
                        }
                    } else {
                        return Ok(None);
                    }
                }
            }
            (_, true) => {
                return Err(Error::InvalidVin(
                    "Empty script_sig for spending a p2pkh".to_owned(),
                ));
            }
            (false, _) => {
                return Err(Error::InvalidVin(
                    "non empty witness for spending a p2pkh".to_owned(),
                ));
            }
        }
    } else if is_p2sh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, false) => {
                let Some(redeem_script) = last_push(script_sig) else {
                    return Ok(None);
                };
                if hash160::Hash::hash(redeem_script).to_byte_array() != script_pub_key[2..22] {
                    return Ok(None);
                }
                if is_p2wpkh(redeem_script) {
                    if let Some(value) = txinwitness.last() {
                        return witness_compressed_pubkey(value, &redeem_script[2..22]);
                    }
                }
            }
            (_, true) => {
                return Err(Error::InvalidVin(
                    "Empty script_sig for spending a p2sh".to_owned(),
                ));
            }
            (true, false) => return Ok(None),
        }
    } else if is_p2wpkh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, true) => {
                if let Some(value) = txinwitness.last() {
                    return witness_compressed_pubkey(value, &script_pub_key[2..22]);
                } else {
                    return Err(Error::InvalidVin("Empty witness".to_owned()));
                }
            }
            (_, false) => {
                return Err(Error::InvalidVin(
                    "Non empty script sig for spending a segwit output".to_owned(),
                ));
            }
            (true, _) => {
                return Err(Error::InvalidVin(
                    "Empty witness for spending a segwit output".to_owned(),
                ));
            }
        }
    } else if is_p2tr(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, true) => {
                // check for the optional annex
                let annex = match txinwitness.last().and_then(|value| value.first()) {
                    Some(&TAPROOT_ANNEX_PREFIX) => 1,
                    Some(_) => 0,
                    None => return Err(Error::InvalidVin("Empty or invalid witness".to_owned())),
                };

                let stack_size = txinwitness.len();
                let effective_stack = stack_size - annex;
                // Script path: control block is the last effective witness item.
                if effective_stack >= 2 {
                    let control_block = &txinwitness[stack_size - annex - 1];
                    if control_block.len() >= 33 && control_block[1..33] == NUMS_H {
                        return Ok(None);
                    }
                }

                // Return the pubkey from the script pubkey
                return XOnlyPublicKey::from_slice(&script_pub_key[2..34])
                    .map_err(Error::Secp256k1Error)
                    .map(|x_only_public_key| {
                        Some(PublicKey::from_x_only_public_key(x_only_public_key, Even))
                    });
            }
            (_, false) => {
                return Err(Error::InvalidVin(
                    "Non empty script sig for spending a segwit output".to_owned(),
                ));
            }
            (true, _) => {
                return Err(Error::InvalidVin(
                    "Empty witness for spending a segwit output".to_owned(),
                ));
            }
        }
    }
    Ok(None)
}
