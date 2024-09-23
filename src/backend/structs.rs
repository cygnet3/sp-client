use bitcoin::{absolute::Height, secp256k1::PublicKey, Amount, BlockHash, ScriptBuf, Txid};

pub struct BlockData {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    pub tweaks: Vec<PublicKey>,
    pub new_utxo_filter: FilterData,
    pub spent_filter: FilterData,
}

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

pub struct FilterData {
    pub block_hash: BlockHash,
    pub data: Vec<u8>,
}
