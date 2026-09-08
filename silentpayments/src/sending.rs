//! The sending component of silent payments.
//!
//! The [`generate_recipient_pubkeys`] function can be used to create outputs for a list of silent payment recipients.
//!
//! Using [`generate_recipient_pubkeys`] will require calculating a
//! `partial_secret` beforehand.
//! To do this, you can use [`calculate_partial_secret`](crate::utils::sending::calculate_partial_secret) from the `utils` module.
//! See the [tests on github](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs)
//! for a concrete example.

use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;

use crate::Result;
use crate::utils::common::SilentPaymentKeyMaterial;
use crate::utils::common::TransactionSharedSecret;
use crate::utils::common::calculate_t_n;
use crate::utils::sending::PartialSecret;
use crate::utils::sending::calculate_ecdh_shared_secret;

/// Create outputs for a given set of silent payment recipients and their corresponding shared secrets.
///
/// When creating the outputs for a transaction, this function should be used to generate the output keys.
///
/// This function should only be used once per transaction! If used multiple times, output key reuse may occur.
///
/// # Arguments
///
/// * `recipients` - A [Vec] of [`SilentPaymentKeyMaterial`] to be paid.
/// * `partial_secret` - [PartialSecret] that represents the sum of the private keys of eligible inputs of the transaction multiplied by the input hash.
///
/// # Returns
///
/// If successful, the function returns a [Result] wrapping a [HashMap] of [`SilentPaymentKeyMaterial`] to a [Vec].
/// The [Vec] contains all the outputs that are associated with that recipient's key material.
///
/// # Errors
///
/// This function will return an error if:
///
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys(
    recipients: Vec<SilentPaymentKeyMaterial>,
    partial_secret: PartialSecret,
) -> Result<HashMap<SilentPaymentKeyMaterial, Vec<XOnlyPublicKey>>> {
    let secp = Secp256k1::new();

    let mut silent_payment_groups: HashMap<
        PublicKey,
        (TransactionSharedSecret, Vec<SilentPaymentKeyMaterial>),
    > = HashMap::new();
    for key_material in recipients {
        let recipient_scan_key = key_material.scan_key();

        if let Some((_, payments)) = silent_payment_groups.get_mut(&recipient_scan_key) {
            payments.push(key_material);
        } else {
            let ecdh_shared_secret =
                calculate_ecdh_shared_secret(&recipient_scan_key, &partial_secret);

            silent_payment_groups
                .insert(recipient_scan_key, (ecdh_shared_secret, vec![key_material]));
        }
    }

    let mut result: HashMap<SilentPaymentKeyMaterial, Vec<XOnlyPublicKey>> = HashMap::new();
    for group in silent_payment_groups.into_values() {
        let (ecdh_shared_secret, recipients) = group;

        for (n, key_material) in recipients.into_iter().enumerate() {
            let t_n = calculate_t_n(&ecdh_shared_secret, n as u32)?;

            let res = t_n.public_key(&secp);
            let reskey = res.combine(&key_material.m_pubkey())?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(key_material).or_default();
            entry.push(reskey_xonly);
        }
    }
    Ok(result)
}
