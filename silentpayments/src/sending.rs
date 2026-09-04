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
use crate::utils::common::SharedSecret;
use crate::utils::common::SilentPaymentKeyMaterial;
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
/// * `recipients` - An iterable list of recipients to be paid. List can contain either [SilentPaymentKeyMaterial] or [crate::SilentPaymentCode].
/// * `partial_secret` - [PartialSecret] that represents the sum of the private keys of eligible inputs of the transaction multiplied by the input hash.
///
/// # Returns
///
/// If successful, the function returns a [Result] wrapping a [HashMap] of each recipient item to a [Vec].
/// The [Vec] contains all the outputs that are associated with that recipient.
/// If the same recipient was added multiple times, this [Vec] will contain multiple elements.
///
/// # Errors
///
/// This function will return an error if:
///
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys<T, I>(
    recipients: I,
    partial_secret: PartialSecret,
) -> Result<HashMap<T, Vec<XOnlyPublicKey>>>
where
    T: Into<SilentPaymentKeyMaterial> + Eq + std::hash::Hash + Clone + Copy,
    I: IntoIterator<Item = T>,
{
    let secp = Secp256k1::new();

    let mut silent_payment_groups: HashMap<PublicKey, (SharedSecret, Vec<T>)> = HashMap::new();
    for recipient in recipients {
        let key_material = recipient.into();

        let recipient_scan_key = key_material.scan_key();

        if let Some((_, payments)) = silent_payment_groups.get_mut(&recipient_scan_key) {
            payments.push(recipient);
        } else {
            let ecdh_shared_secret =
                calculate_ecdh_shared_secret(&recipient_scan_key, &partial_secret);

            silent_payment_groups.insert(recipient_scan_key, (ecdh_shared_secret, vec![recipient]));
        }
    }

    let mut result: HashMap<T, Vec<XOnlyPublicKey>> = HashMap::new();
    for group in silent_payment_groups.into_values() {
        let (ecdh_shared_secret, recipients) = group;

        for (n, recipient) in recipients.into_iter().enumerate() {
            let recipient_key_material = recipient.into();
            let t_n = calculate_t_n(&ecdh_shared_secret, n as u32)?;

            let res = t_n.public_key(&secp);
            let reskey = res.combine(&recipient_key_material.m_pubkey())?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(recipient).or_default();
            entry.push(reskey_xonly);
        }
    }
    Ok(result)
}
