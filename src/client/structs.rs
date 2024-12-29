use anyhow::Error;
use bitcoin::{
    absolute::Height,
    address::NetworkUnchecked,
    key::Secp256k1,
    secp256k1::{PublicKey, SecretKey},
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut,
};
use serde::{Deserialize, Serialize};
use silentpayments::utils::SilentPaymentAddress;

type SpendingTxId = String;
type MinedInBlock = String;

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
    pub label: Option<String>,
    pub spend_status: OutputSpendStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum RecipientAddress {
    LegacyAddress(Address<NetworkUnchecked>),
    SpAddress(SilentPaymentAddress), // We need to implement Serialize for SilentPaymentAddress
    Data(Vec<u8>),     // OpReturn output
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Recipient {
    pub address: RecipientAddress, // either old school or silent payment
    pub amount: Amount,            // must be 0 if address is Data.
    pub nb_outputs: u32,           // if address is not SP, only 1 is valid
    pub outputs: Vec<TxOut>,
}

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

impl Into<PublicKey> for SpendKey {
    fn into(self) -> PublicKey {
        match self {
            Self::Secret(k) => {
                let secp = Secp256k1::signing_only();
                k.public_key(&secp)
            }
            Self::Public(p) => p,
        }
    }
}
