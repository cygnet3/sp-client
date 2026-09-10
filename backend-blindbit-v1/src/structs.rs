use std::collections::{HashMap, HashSet};

use crate::api_structs::FilterResponse;
use bitcoin::{
    BlockHash, OutPoint,
    absolute::Height,
    bip158::BlockFilter,
    hashes::{Hash, sha256},
    secp256k1::PublicKey,
};
use spdk_core::chain::BlockData;

pub struct BlindbitV1BlockData {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    pub tweaks: Vec<PublicKey>,
    pub new_utxo_filter: FilterData,
    pub spent_filter: FilterData,
}

pub struct FilterData {
    pub block_hash: BlockHash,
    pub data: Vec<u8>,
}

impl From<FilterResponse> for FilterData {
    fn from(value: FilterResponse) -> Self {
        Self {
            block_hash: value.block_hash,
            data: value.data.hex,
        }
    }
}

impl BlockData for BlindbitV1BlockData {
    fn blkheight(&self) -> Height {
        self.blkheight
    }

    fn blkhash(&self) -> BlockHash {
        self.blkhash
    }

    fn tweaks(&self) -> Vec<PublicKey> {
        self.tweaks.clone()
    }

    fn check_match_outputs(&self, candidate_spks: Vec<&[u8; 34]>) -> anyhow::Result<bool> {
        // check output scripts
        let output_keys: Vec<_> = candidate_spks
            .into_iter()
            .map(|spk| spk[2..].as_ref())
            .collect();

        // note: match will always return true for an empty query!
        if !output_keys.is_empty() {
            let filter = BlockFilter::new(&self.new_utxo_filter.data);

            Ok(filter.match_any(&self.blkhash, &mut output_keys.into_iter())?)
        } else {
            Ok(false)
        }
    }

    // Check if this block contains relevant transactions
    fn check_match_inputs(&self, owned_outpoints: &HashSet<OutPoint>) -> anyhow::Result<bool> {
        let input_hashes_map = self.input_hashes_map(owned_outpoints)?;

        let input_hashes: Vec<[u8; 8]> = input_hashes_map.keys().cloned().collect();

        // note: match will always return true for an empty query!
        if !input_hashes.is_empty() {
            let filter = BlockFilter::new(&self.spent_filter.data);

            Ok(filter.match_any(&self.blkhash, &mut input_hashes.into_iter())?)
        } else {
            Ok(false)
        }
    }

    fn input_hashes_map(
        &self,
        owned_outpoints: &HashSet<OutPoint>,
    ) -> anyhow::Result<HashMap<[u8; 8], OutPoint>> {
        let mut map: HashMap<[u8; 8], OutPoint> = HashMap::new();

        for outpoint in owned_outpoints {
            let mut arr = [0u8; 68];
            arr[..32].copy_from_slice(&outpoint.txid.to_raw_hash().to_byte_array());
            arr[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
            arr[36..].copy_from_slice(&self.blkhash.to_byte_array());
            let hash = sha256::Hash::hash(&arr);

            let mut res = [0u8; 8];
            res.copy_from_slice(&hash[..8]);

            map.insert(res, *outpoint);
        }

        Ok(map)
    }
}
