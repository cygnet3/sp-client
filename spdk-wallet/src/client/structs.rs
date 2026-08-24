use std::collections::HashMap;
use std::str::FromStr;

use anyhow::Error;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Address, Amount, Network, OutPoint, Transaction};
use serde::{Deserialize, Serialize};
use silentpayments::SilentPaymentCode;
use silentpayments::TransactionSharedSecret;
use silentpayments::secp256k1::PublicKey as SpPublicKey;

use spdk_core::updater::DiscoveredOutput;

use super::coin_select::Strategy;

// re-export from bdk_coin_select, as we use this in the api
pub use bdk_coin_select::FeeRate;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum RecipientAddress {
    LegacyAddress(Address<NetworkUnchecked>),
    SpCode(SilentPaymentCode),
    Data(Vec<u8>), // OpReturn output
}

impl TryFrom<String> for RecipientAddress {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(sp_code) = SilentPaymentCode::try_from(value.as_str()) {
            Ok(Self::SpCode(sp_code))
        } else if let Ok(legacy_address) = Address::from_str(&value) {
            Ok(Self::LegacyAddress(legacy_address))
        } else if let Ok(data) = Vec::from_hex(&value) {
            Ok(Self::Data(data))
        } else {
            Err(anyhow::Error::msg("Unknown recipient address type"))
        }
    }
}

impl From<RecipientAddress> for String {
    fn from(value: RecipientAddress) -> Self {
        match value {
            RecipientAddress::LegacyAddress(address) => address.assume_checked().to_string(),
            RecipientAddress::SpCode(sp_code) => sp_code.to_string(),
            RecipientAddress::Data(data) => data.to_lower_hex_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Recipient {
    pub address: RecipientAddress, // either old school or silent payment
    pub amount: Amount,            // must be 0 if address is Data.
}

#[derive(Debug, Clone)]
// this will be replaced by a proper psbt as soon as sp support is standardised
pub struct SilentPaymentUnsignedTransaction {
    pub selected_utxos: Vec<(OutPoint, DiscoveredOutput)>,
    pub recipients: Vec<Recipient>,
    pub shared_secrets: HashMap<SpPublicKey, TransactionSharedSecret>,
    pub unsigned_tx: Option<Transaction>,
    pub network: Network,
    /// Wallet change amount (zero for drain / changeless selections).
    pub change: Amount,
    /// Indices into `recipients` that are change outputs.
    pub change_indexes: Vec<usize>,
    pub fee: Amount,
    pub actual_fee_rate: FeeRate,
    pub strategy: Strategy,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum SpendKey {
    Secret(SecretKey),
    Public(PublicKey),
}

impl Drop for SpendKey {
    fn drop(&mut self) {
        if let Self::Secret(sk) = self {
            // Erase the key material before dropping.
            // secp256k1::SecretKey does not implement Zeroize (its inner
            // array is private); non_secure_erase() is the zeroize-documented
            // erase path (volatile C-level memset, cannot be optimized away).
            sk.non_secure_erase();
        }
    }
}

impl TryInto<SecretKey> for SpendKey {
    type Error = anyhow::Error;
    fn try_into(self) -> std::prelude::v1::Result<SecretKey, Error> {
        match self {
            Self::Secret(k) => Ok(k),
            Self::Public(_) => Err(Error::msg("Can't take SecretKey from Public")),
        }
    }
}

impl From<&SpendKey> for PublicKey {
    fn from(value: &SpendKey) -> Self {
        match value {
            SpendKey::Secret(k) => {
                let secp = Secp256k1::signing_only();
                k.public_key(&secp)
            }
            SpendKey::Public(p) => *p,
        }
    }
}

impl From<SpendKey> for PublicKey {
    fn from(value: SpendKey) -> Self {
        (&value).into()
    }
}
