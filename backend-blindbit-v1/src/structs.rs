use std::collections::HashSet;

use crate::api_structs::FilterResponse;
use crate::utils::input_hashes_map;
use bitcoin::{BlockHash, OutPoint, absolute::Height, bip158::BlockFilter, secp256k1::PublicKey};
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
        let input_hashes_map = input_hashes_map(owned_outpoints, self.blkhash)?;

        let input_hashes: Vec<[u8; 8]> = input_hashes_map.keys().cloned().collect();

        // note: match will always return true for an empty query!
        if !input_hashes.is_empty() {
            let filter = BlockFilter::new(&self.spent_filter.data);

            Ok(filter.match_any(&self.blkhash, &mut input_hashes.into_iter())?)
        } else {
            Ok(false)
        }
    }
}
