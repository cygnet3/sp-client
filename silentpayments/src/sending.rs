//! The sending component of silent payments.
//!
//! The [`generate_recipient_pubkeys`] function creates taproot output keys for silent payment recipients.
//!
//! Callers must supply a [`TransactionSharedSecret`] per unique recipient scan key.
//! On the sender side, build secrets from a [`GlobalSenderEcdhShare`](crate::utils::sending::GlobalSenderEcdhShare)
//! or from combined [`PartialSenderEcdhShare`](crate::utils::sending::PartialSenderEcdhShare)s.
//! See [the test vectors](https://github.com/cygnet3/spdk/blob/master/silentpayments/tests/vector_tests.rs)
//! for a full example.

use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;

use crate::utils::common::SilentPaymentKeyMaterial;
use crate::utils::common::TransactionSharedSecret;
use crate::utils::common::calculate_t_n;
use crate::{Error, Result};

/// Create taproot output keys for a set of silent payment recipients.
///
/// Recipients are grouped by scan key. Within each group the BIP352 output-index counter `n`
/// increments in the order the key material entries appear in `recipients`, so callers must pass
/// them in their intended output order. Calling this function more than once for the same
/// transaction with the same `shared_secrets` will restart every `n` counter at 0, producing
/// duplicate output keys and breaking recipient privacy — call it exactly once per transaction.
///
/// # Arguments
///
/// * `recipients` - Silent payment key material to pay, in output order. Multiple entries may
///   share the same scan key; `n` is assigned within that scan-key group in the order given.
/// * `shared_secrets` - One [`TransactionSharedSecret`] per unique scan key, keyed by that scan
///   `PublicKey`. Each entry's internally stored scan key must equal its map key.
///
/// # Returns
///
/// A [`HashMap`] whose keys are the original key material entries from `recipients` and whose
/// values are the corresponding taproot [`XOnlyPublicKey`] outputs.
///
/// # Errors
///
/// This function will return an error if:
///
/// * A scan key has no corresponding entry in `shared_secrets`, or the entry's stored scan key
///   does not match its map key.
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys<C, T, I>(
    secp: &Secp256k1<C>,
    recipients: I,
    shared_secrets: &HashMap<PublicKey, TransactionSharedSecret>,
) -> Result<HashMap<T, Vec<XOnlyPublicKey>>>
where
    C: secp256k1::Signing,
    T: Into<SilentPaymentKeyMaterial> + Eq + std::hash::Hash + Clone + Copy,
    I: IntoIterator<Item = T>,
{
    let mut silent_payment_groups: HashMap<PublicKey, (TransactionSharedSecret, Vec<T>)> =
        HashMap::new();

    for recipient in recipients {
        let key_material: SilentPaymentKeyMaterial = recipient.into();
        let recipient_scan_key = key_material.scan_key();

        if let Some((_, payments)) = silent_payment_groups.get_mut(&recipient_scan_key) {
            payments.push(recipient);
        } else {
            let shared_secret = shared_secrets.get(&recipient_scan_key).ok_or_else(|| {
                Error::GenericError(format!(
                    "Missing shared secret for scan key {recipient_scan_key}"
                ))
            })?;
            if shared_secret.as_recipient_scan_key() != &recipient_scan_key {
                return Err(Error::GenericError(format!(
                    "Shared secret stored under scan key {recipient_scan_key} has mismatched \
                     internal scan key {}",
                    shared_secret.as_recipient_scan_key()
                )));
            }
            silent_payment_groups.insert(recipient_scan_key, (*shared_secret, vec![recipient]));
        }
    }

    let mut result: HashMap<T, Vec<XOnlyPublicKey>> = HashMap::new();
    for (ecdh_shared_secret, recipients) in silent_payment_groups.into_values() {
        for (n, recipient) in recipients.into_iter().enumerate() {
            let key_material: SilentPaymentKeyMaterial = recipient.into();
            let t_n = calculate_t_n(&ecdh_shared_secret, n as u32)?;

            let res = t_n.public_key(secp);
            let reskey = res.combine(&key_material.m_pubkey())?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            result.entry(recipient).or_default().push(reskey_xonly);
        }
    }
    Ok(result)
}
