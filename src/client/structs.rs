use std::str::FromStr;

use anyhow::Error;
use bitcoin::{
    absolute::Height,
    address::NetworkUnchecked,
    hex::{DisplayHex, FromHex},
    key::Secp256k1,
    secp256k1::{PublicKey, SecretKey},
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction,
};
use serde::{Deserialize, Serialize};
use silentpayments::{receiving::Label, SilentPaymentAddress};

type SpendingTxId = [u8; 32];
type MinedInBlock = [u8; 32];

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum OutputSpendStatus {
    Unspent,
    Spent(SpendingTxId),
    Mined(MinedInBlock),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OwnedOutput {
    pub blockheight: Height,
    pub tweak: [u8; 32], // scalar in big endian format
    pub amount: Amount,
    pub script: ScriptBuf,
    pub label: Option<Label>,
    pub spend_status: OutputSpendStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum RecipientAddress {
    LegacyAddress(Address<NetworkUnchecked>),
    SpAddress(SilentPaymentAddress),
    Data(Vec<u8>), // OpReturn output
}

impl TryFrom<String> for RecipientAddress {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(sp_address) = SilentPaymentAddress::try_from(value.as_str()) {
            Ok(Self::SpAddress(sp_address.into()))
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
            RecipientAddress::SpAddress(sp_address) => sp_address.to_string(),
            RecipientAddress::Data(data) => data.to_lower_hex_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Recipient {
    pub address: RecipientAddress, // either old school or silent payment
    pub amount: Amount,            // must be 0 if address is Data.
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
// this will be replaced by a proper psbt as soon as sp support is standardised
pub struct SilentPaymentUnsignedTransaction {
    pub selected_utxos: Vec<(OutPoint, OwnedOutput)>,
    pub recipients: Vec<Recipient>,
    pub partial_secret: SecretKey,
    pub unsigned_tx: Option<Transaction>,
    pub network: Network,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum SpendKey {
    Secret(SecretKey),
    Public(PublicKey),
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
        value.into()
    }
}
