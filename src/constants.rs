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

pub const PSBT_SP_PREFIX: &str = "sp";
pub const PSBT_SP_SUBTYPE: u8 = 0;
pub const PSBT_SP_TWEAK_KEY: &str = "tweak";
pub const PSBT_SP_ADDRESS_KEY: &str = "address";

pub const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub struct LogEntry {
    // pub time_millis: i64,
    // pub level: i32,
    // pub tag: String,
    pub msg: String,
}

pub struct SyncStatus {
    pub peer_count: u32,
    pub blockheight: u64,
    pub bestblockhash: String,
}
