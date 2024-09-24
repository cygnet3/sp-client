use anyhow::Error;
use bitcoin::{
    absolute::Height,
    key::Secp256k1,
    secp256k1::{PublicKey, SecretKey},
    Amount, ScriptBuf,
};
use serde::{Deserialize, Serialize};

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
pub struct Recipient {
    pub address: String, // either old school or silent payment
    pub amount: Amount,
    pub nb_outputs: u32, // if address is not SP, only 1 is valid
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
