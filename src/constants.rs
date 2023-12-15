use serde::{Serialize, Deserialize};

#[derive(Deserialize, Serialize)]
pub enum WalletType {
    Mnemonic(String),
    // scan_sk_hex, spend_sk_hex
    PrivateKeys((String, String)),
    // scan_sk_hex, spend_pk_hex
    ReadOnly((String, String)),
}

pub struct LogEntry {
    // pub time_millis: i64,
    // pub level: i32,
    // pub tag: String,
    pub msg: String,
}
