//! Receiving utility functions.
use crate::{
    Error, Result,
    utils::{
        common::{NonEmptyArray, OutPoint, SharedSecret},
        script::{is_p2pkh, is_p2sh, is_p2wpkh},
    },
};

pub use crate::utils::script::{is_eligible, is_p2tr};
use bitcoin_hashes::{Hash, hash160};
use secp256k1::{Parity::Even, XOnlyPublicKey, ecdh::shared_secret_point};
use secp256k1::{PublicKey, SecretKey};

use super::{
    COMPRESSED_PUBKEY_SIZE, NUMS_H, OP_PUSHBYTES_1, OP_PUSHBYTES_75, OP_PUSHDATA1, OP_PUSHDATA2,
    OP_PUSHDATA4, TAPROOT_ANNEX_PREFIX, hash::calculate_input_hash,
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
/// This is useful in combination with the [calculate_ecdh_shared_secret] function, but can also be used
/// by indexing servers that don't have access to the recipient scan key.
///
/// # Arguments
///
/// * `input_pub_keys` - The list of public keys that are used as input for this transaction. Only the public keys for inputs that are silent payment eligible should be given.
/// * `outpoints_data` - All prevout outpoints used as input for this transaction. Note that the txid is given in String format, which is displayed in reverse order from the inner byte array.
///
/// # Returns
///
/// This function returns the tweak data for this transaction. The tweak data is an intermediary result that can be used to calculate the final shared secret.
///
/// # Errors
///
/// This function will error if:
///
/// * The input public keys array is of length zero, or the summing results in an invalid key.
/// * The outpoints_data is of length zero, or invalid.
/// * Elliptic curve computation results in an invalid public key.
pub fn calculate_tweak_data(
    input_pub_keys: &[&PublicKey],
    outpoints_data: &[OutPoint],
) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::verification_only();
    let A_sum = PublicKey::combine_keys(input_pub_keys)?;

    let outpoints = NonEmptyArray::new(outpoints_data)?;
    let input_hash = calculate_input_hash(outpoints.min(), A_sum);

    Ok(A_sum.mul_tweak(&secp, &input_hash)?)
}

/// Calculate the shared secret of a transaction.
///
/// # Arguments
///
/// * `tweak_data` - The tweak data of the transaction, see `calculate_tweak_data`.
/// * `b_scan` - The scan private key used by the wallet.
///
/// # Returns
///
/// This function returns the shared secret of this transaction. This shared secret can be used to scan the transaction of outputs that are for the current user. See [`Receiver::scan_transaction`](crate::receiving::Receiver::scan_transaction).
pub fn calculate_ecdh_shared_secret(tweak_data: &PublicKey, b_scan: &SecretKey) -> SharedSecret {
    let mut ss_bytes = [0u8; 65];
    ss_bytes[0] = 0x04;

    // Using `shared_secret_point` to ensure the multiplication is constant time
    ss_bytes[1..].copy_from_slice(&shared_secret_point(tweak_data, b_scan));

    SharedSecret(PublicKey::from_slice(&ss_bytes).expect("guaranteed to be a point on the curve"))
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
