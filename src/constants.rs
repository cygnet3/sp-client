use serde::{Serialize, Deserialize};

type SecretKeyString = String;
type PublicKeyString = String;

#[derive(Deserialize, Serialize)]
pub enum WalletType {
    New,
    Mnemonic(String),
    // scan_sk_hex, spend_sk_hex
    PrivateKeys(SecretKeyString, SecretKeyString),
    // scan_sk_hex, spend_pk_hex
    ReadOnly(SecretKeyString, PublicKeyString),
}

pub struct LogEntry {
    // pub time_millis: i64,
    // pub level: i32,
    // pub tag: String,
    pub msg: String,
}
