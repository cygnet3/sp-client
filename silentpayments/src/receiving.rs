//! The receiving component of silent payments.
//!
//! For receiving, we use the [`Receiver`] struct.
//! This struct does not contain any private key information,
//! so as to avoid having access to secret data.
//!
//! After creating a [`Receiver`] object, you can call [`scan_transaction`](Receiver::scan_transaction),
//! to scan a specific transaction for outputs belonging to this receiver.
//!
//! This requires a [`TransactionSharedSecret`] for the transaction. Compute it from
//! [`PublicTweakData`](crate::utils::receiving::PublicTweakData) and the scan private key via
//! [`TransactionSharedSecret::new_from_public_tweak_data`].
//!
//! For a concrete example, see the [test vectors](https://github.com/cygnet3/spdk/blob/master/silentpayments/tests/vector_tests.rs)
//! or the `find_output` example.
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::{
    Error, Network, Result, SilentPaymentCode, SpVersion,
    utils::{
        OP_1, OP_PUSHBYTES_32,
        common::{TransactionSharedSecret, calculate_P_n, calculate_t_n},
        hash::calculate_label_hash,
    },
};
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
    ser::{SerializeStruct, SerializeTuple},
};

/// A Silent payment receiving label.
#[derive(Eq, PartialEq, Clone)]
pub struct Label {
    s: Scalar,
}

impl Label {
    pub fn new(b_scan: SecretKey, m: u32) -> Label {
        Label {
            s: calculate_label_hash(b_scan, m),
        }
    }

    pub fn into_inner(self) -> Scalar {
        self.s
    }

    pub fn as_inner(&self) -> &Scalar {
        &self.s
    }

    pub fn as_string(&self) -> String {
        hex::encode(self.as_inner().to_be_bytes())
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl std::hash::Hash for Label {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let bytes = self.s.to_be_bytes();
        bytes.hash(state);
    }
}

impl From<Scalar> for Label {
    fn from(s: Scalar) -> Self {
        Label { s }
    }
}

impl TryFrom<String> for Label {
    type Error = Error;

    fn try_from(s: String) -> Result<Label> {
        Label::try_from(&s[..])
    }
}

impl TryFrom<&str> for Label {
    type Error = Error;

    fn try_from(s: &str) -> Result<Label> {
        // Is it valid hex?
        let bytes = hex::decode(s)?;
        // Is it 32B long?
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::InvalidLabel("Label must be 32 bytes (256 bits) long".to_owned())
        })?;
        // Is it on the curve? If yes, push it on our labels list
        Ok(Label::from(Scalar::from_be_bytes(bytes)?))
    }
}

impl From<Label> for Scalar {
    fn from(l: Label) -> Self {
        l.s
    }
}

impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: String = String::deserialize(deserializer)?;
        value.try_into().map_err(serde::de::Error::custom)
    }
}

/// A struct representing a silent payment recipient.
///
/// It can be used to scan for transaction outputs belonging to us by using the [`scan_transaction`](Receiver::scan_transaction) function.
/// It optionally supports labels, which it manages internally.
/// Labels can be added with [`add_label`](Receiver::add_label).
#[derive(Debug, Clone, PartialEq)]
pub struct Receiver {
    version: SpVersion,
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
    change_label: Label, // To be able to tell which label is the change
    labels: HashMap<PublicKey, Label>,
    pub network: Network,
}

struct SerializablePubkey([u8; 33]);

struct SerializableHashMap(HashMap<PublicKey, Label>);

impl Serialize for SerializablePubkey {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for element in &self.0[..] {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for SerializablePubkey {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SerializablePubkeyVisitor;

        impl<'de> Visitor<'de> for SerializablePubkeyVisitor {
            type Value = SerializablePubkey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of 33 bytes")
            }

            fn visit_seq<V>(
                self,
                mut seq: V,
            ) -> std::prelude::v1::Result<SerializablePubkey, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut arr = [0u8; 33];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(SerializablePubkey(arr))
            }
        }

        deserializer.deserialize_tuple(33, SerializablePubkeyVisitor)
    }
}

impl Serialize for SerializableHashMap {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let pairs: Vec<(SerializablePubkey, Label)> = self
            .0
            .iter()
            .map(|(pubkey, label)| (SerializablePubkey(pubkey.serialize()), label.to_owned()))
            .collect();
        // Now serialize `pairs` as a vector of tuples
        pairs.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializableHashMap {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pairs: Vec<(SerializablePubkey, Label)> = Deserialize::deserialize(deserializer)?;
        let mut map: HashMap<PublicKey, Label> = HashMap::new();
        for (ser_pubkey, label) in pairs {
            map.insert(PublicKey::from_slice(&ser_pubkey.0).unwrap(), label);
        }
        Ok(SerializableHashMap(map))
    }
}

impl Serialize for Receiver {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Receiver", 5)?;
        state.serialize_field::<u8>("version", &self.version.into())?;
        state.serialize_field("network", &self.network)?;
        state.serialize_field(
            "scan_pubkey",
            &SerializablePubkey(self.scan_pubkey.serialize()),
        )?;
        state.serialize_field(
            "spend_pubkey",
            &SerializablePubkey(self.spend_pubkey.serialize()),
        )?;
        state.serialize_field("change_label", &self.change_label)?;
        state.serialize_field("labels", &SerializableHashMap(self.labels.clone()))?;
        state.end()
    }
}

#[derive(Deserialize)]
struct ReceiverHelper {
    version: u8,
    network: Network,
    scan_pubkey: SerializablePubkey,
    spend_pubkey: SerializablePubkey,
    change_label: String,
    labels: SerializableHashMap,
}

impl<'de> Deserialize<'de> for Receiver {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = ReceiverHelper::deserialize(deserializer)?;
        Ok(Receiver {
            version: helper.version.try_into().unwrap(),
            network: helper.network,
            scan_pubkey: PublicKey::from_slice(&helper.scan_pubkey.0).unwrap(),
            spend_pubkey: PublicKey::from_slice(&helper.spend_pubkey.0).unwrap(),
            change_label: Label::try_from(helper.change_label).unwrap(),
            labels: helper.labels.0,
        })
    }
}

impl Receiver {
    pub fn new(
        version: SpVersion,
        scan_pubkey: PublicKey,
        spend_pubkey: PublicKey,
        change_label: Label,
        network: Network,
    ) -> Result<Self> {
        let labels: HashMap<PublicKey, Label> = HashMap::new();

        let mut receiver = Receiver {
            version,
            scan_pubkey,
            spend_pubkey,
            change_label: change_label.clone(),
            labels,
            network,
        };

        // This checks that the change_label produces a valid key at each step
        receiver.add_label(change_label)?;

        Ok(receiver)
    }

    /// Takes a [Label] and adds it to the list of labels that this recipient uses.
    /// Returns a bool on success, [true] if the label was new, [false] if it already existed in our list.
    pub fn add_label(&mut self, label: Label) -> Result<bool> {
        let secp = Secp256k1::signing_only();

        let m = SecretKey::from_slice(&label.as_inner().to_be_bytes())?;
        let mG = m.public_key(&secp);

        // check that the combined key with spend_key is valid
        mG.combine(&self.spend_pubkey)?;

        Ok(self.labels.insert(mG, label).is_none())
    }

    /// List all currently known labels used by this recipient.
    pub fn list_labels(&self) -> HashSet<Label> {
        self.labels.values().cloned().collect()
    }

    /// Get the silent payment code for a specific label.
    ///
    /// # Arguments
    ///
    /// * `label` - A reference to a [Label].
    ///
    /// # Returns
    ///
    /// If successful, the function returns a [Result] wrapping a [SilentPaymentCode].
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * If the label is not known for this recipient.
    /// * If key addition results in an invalid key.
    pub fn receiving_code_for_label(&self, label: &Label) -> Result<SilentPaymentCode> {
        for (mG, l) in self.labels.iter() {
            if l == label {
                let m_pubkey = mG.combine(&self.spend_pubkey)?;
                let code =
                    SilentPaymentCode::new(self.version, self.scan_pubkey, m_pubkey, self.network);
                return Ok(code);
            }
        }
        Err(Error::InvalidLabel("Label not known".to_owned()))
    }

    /// Get the silent payment change code for this [`Receiver`].
    ///
    /// This is the static code associated with the change label, as described in
    /// BIP352. Wallets can create silent-payment-native change by sending to this
    /// code, much like sending to a normal silent payment code.
    ///
    /// Important: this code should never be shown to the user.
    pub fn change_code(&self) -> SilentPaymentCode {
        let sk = SecretKey::from_slice(&self.change_label.as_inner().to_be_bytes())
            .expect("Unexpected invalid change label");
        let pk = sk.public_key(&Secp256k1::signing_only());
        let m_pubkey = pk
            .combine(&self.spend_pubkey)
            .expect("Unexpected invalid pubkey");
        SilentPaymentCode::new(self.version, self.scan_pubkey, m_pubkey, self.network)
    }

    /// Get the default, no-label silent payment code.
    pub fn receiving_code(&self) -> SilentPaymentCode {
        SilentPaymentCode::new(
            self.version,
            self.scan_pubkey,
            self.spend_pubkey,
            self.network,
        )
    }

    /// Scans a transaction for outputs belonging to us.
    ///
    /// # Arguments
    ///
    /// * `ecdh_shared_secret` -  The ECDH shared secret between sender and recipient, the result of elliptic-curve multiplication of `(input_hash * sum_inputs_pubkeys) * scan_private_key`.
    /// * `pubkeys_to_check` - A [HashSet] of public keys of all (unspent) taproot output of the transaction.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a [Result] wrapping a [HashMap] of labels to a map of outputs to key tweaks (since the same label may have been paid multiple times in one transaction). The key tweaks can be added to the wallet's spending private key to produce a key that can spend the utxo. A resulting [HashMap] of length 0 implies none of the outputs are owned by us.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * One of the public keys to scan can't be parsed into a valid x-only public key.
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious.
    pub fn scan_transaction(
        &self,
        ecdh_shared_secret: &TransactionSharedSecret,
        pubkeys_to_check: &[XOnlyPublicKey],
    ) -> Result<HashMap<Option<Label>, HashMap<XOnlyPublicKey, Scalar>>> {
        let secp = secp256k1::Secp256k1::new();

        let mut found: HashMap<Option<Label>, HashMap<XOnlyPublicKey, Scalar>> = HashMap::new();
        let mut n_found: u32 = 0;
        let mut n: u32 = 0;
        while n_found == n {
            let t_n: SecretKey = calculate_t_n(ecdh_shared_secret, n)?;
            let P_n: PublicKey = calculate_P_n(&self.spend_pubkey, t_n.into())?;
            let P_n_xonly = P_n.x_only_public_key().0;
            if pubkeys_to_check.iter().any(|p| p.eq(&P_n_xonly)) {
                n_found += 1;
                found.entry(None).or_default().insert(P_n_xonly, t_n.into());
            } else {
                // We subtract P_n from each outputs to check and see if match a public key in our label list
                'outer: for p in pubkeys_to_check {
                    let even_output = p.public_key(Parity::Even);
                    let odd_output = p.public_key(Parity::Odd);
                    let even_diff = even_output.combine(&P_n.negate(&secp))?;
                    let odd_diff = odd_output.combine(&P_n.negate(&secp))?;

                    for diff in [even_diff, odd_diff] {
                        if let Some(label) = self.labels.get(&diff) {
                            n_found += 1;
                            let t_n_label = t_n.add_tweak(label.as_inner())?;
                            found
                                .entry(Some(label.clone()))
                                .or_default()
                                .insert(*p, t_n_label.into());
                            break 'outer;
                        }
                    }
                }
            }
            n += 1;
        }
        Ok(found)
    }

    /// Get the possible ScriptPubKeys from a transaction's tweak data.
    /// Using the tweak data, this function will calculate the resulting script, given the assumption that this transaction is a payment to us.
    /// This Script can be useful for BIP158 block filters.
    ///
    /// # Arguments
    ///
    /// * `ecdh_shared_secret` -  The ECDH shared secret between sender and recipient as a PublicKey, the result of elliptic-curve multiplication of `(input_hash * sum_inputs_pubkeys) * scan_private_key`.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a [Result] wrapping a [HashMap] that maps an optional [Label] to a Script as a 34-byte vector. The script has the following format: `OP_PUSHNUM_1 OP_PUSHBYTES_32 taproot_output`
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious.
    pub fn script_pubkeys_from_shared_secret(
        &self,
        ecdh_shared_secret: &TransactionSharedSecret,
    ) -> Result<HashMap<Option<Label>, [u8; 34]>> {
        let t_0: SecretKey = calculate_t_n(ecdh_shared_secret, 0)?;
        let P_0: PublicKey = calculate_P_n(&self.spend_pubkey, t_0.into())?;
        let output_key_bytes = P_0.x_only_public_key().0.serialize();

        let mut res = HashMap::new();

        let mut spk = [0u8; 34];
        // OP_PUSHNUM_1 OP_PUSHBYTES_32 taproot output key
        spk[..2].copy_from_slice(&[OP_1, OP_PUSHBYTES_32]);
        spk[2..].copy_from_slice(&output_key_bytes);

        res.insert(None, spk);

        for (mG, label) in &self.labels {
            let B_m = mG.combine(&self.spend_pubkey)?;
            let P_m0 = calculate_P_n(&B_m, t_0.into())?;
            let output_key_bytes = P_m0.x_only_public_key().0.serialize();

            let mut spk = [0u8; 34];
            spk[..2].copy_from_slice(&[OP_1, OP_PUSHBYTES_32]);
            spk[2..].copy_from_slice(&output_key_bytes);

            res.insert(Some(label.clone()), spk);
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{Secp256k1, SecretKey};

    use crate::SpVersion;

    use super::Label;

    #[test]
    fn string_to_label_success() {
        let s: String =
            "8e4bbee712779f746337cadf39e8b1eab8e8869dd40f2e3a7281113e858ffc0b".to_owned();
        Label::try_from(s).unwrap();
    }

    #[test]
    fn deserialize_label() {
        let s: String =
            "\"8e4bbee712779f746337cadf39e8b1eab8e8869dd40f2e3a7281113e858ffc0b\"".to_owned();

        let label: Label = serde_json::from_str(&s).unwrap();

        let label_str = serde_json::to_string(&label).unwrap();

        assert_eq!(label_str, s);
    }

    #[test]
    fn string_to_label_failure() {
        // Invalid characters
        let s: String = "deadbeef?:{+!&".to_owned();
        Label::try_from(s).unwrap_err();
        // Invalid length
        let s: String = "deadbee".to_owned();
        Label::try_from(s).unwrap_err();
        // Not 32B
        let s: String = "deadbeef".to_owned();
        Label::try_from(s).unwrap_err();
    }

    #[test]
    fn serialize_deserialize_receiver() {
        let scan_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let spend_key = SecretKey::from_slice(&[2u8; 32]).unwrap();

        let change_label = Label::new(scan_key, 0);

        let secp = Secp256k1::new();

        let receiver = super::Receiver::new(
            SpVersion::ZERO,
            scan_key.public_key(&secp),
            spend_key.public_key(&secp),
            change_label,
            crate::Network::Testnet,
        )
        .unwrap();

        let serialized = serde_json::to_string(&receiver).unwrap();
        let deserialized: super::Receiver = serde_json::from_str(&serialized).unwrap();

        assert_eq!(receiver, deserialized);
    }
}
