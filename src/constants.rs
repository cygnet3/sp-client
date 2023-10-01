use bitcoin::Script;
use serde::Serialize;
use turbosql::Turbosql;


pub struct LogEntry {
    // pub time_millis: i64,
    // pub level: i32,
    // pub tag: String,
    pub msg: String,
}

pub struct WalletStatus {
    pub amount: u32,
    pub scan_height: u32,
    pub block_tip: u32,
}

pub struct ScanProgress {
    pub start: u32,
    pub current: u32,
    pub end: u32,
}

#[derive(Turbosql, Default, Debug, Serialize)]
pub struct OwnedOutputs {
    pub rowid: Option<i64>,
    pub blockheight: Option<u32>,
    pub amount: Option<u32>,
    pub script: Option<Script>,
}

#[derive(Turbosql, Default, Debug, Serialize)]
pub struct ScanHeight {
    pub rowid: Option<i64>,
    pub scanheight: Option<u32>,
}
