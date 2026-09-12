use bitcoin::{Amount, ScriptBuf, Txid};

pub struct UtxoData {
    pub txid: Txid,
    pub vout: u32,
    pub value: Amount,
    pub scriptpubkey: ScriptBuf,
    pub spent: bool,
}

pub struct SpentIndexData {
    pub data: Vec<Vec<u8>>,
}
