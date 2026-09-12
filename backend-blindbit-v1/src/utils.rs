use std::collections::{HashMap, HashSet};

use bitcoin::{
    BlockHash, OutPoint,
    hashes::{Hash, sha256},
};

pub fn input_hashes_map(
    owned_outpoints: &HashSet<OutPoint>,
    blkhash: BlockHash,
) -> anyhow::Result<HashMap<[u8; 8], OutPoint>> {
    let mut map: HashMap<[u8; 8], OutPoint> = HashMap::new();

    for outpoint in owned_outpoints {
        let mut arr = [0u8; 68];
        arr[..32].copy_from_slice(&outpoint.txid.to_raw_hash().to_byte_array());
        arr[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
        arr[36..].copy_from_slice(&blkhash.to_byte_array());
        let hash = sha256::Hash::hash(&arr);

        let mut res = [0u8; 8];
        res.copy_from_slice(&hash[..8]);

        map.insert(res, *outpoint);
    }

    Ok(map)
}
