use std::{collections::HashSet, ops::RangeInclusive, pin::Pin};

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{Amount, BlockHash, OutPoint, absolute::Height, secp256k1::PublicKey};
use futures::Stream;

use super::structs::UtxoData;

pub type BoxedBlockData = Box<dyn BlockData + Send + Sync>;

#[async_trait]
pub trait ChainBackend {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<Height>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BoxedBlockData>> + Send>>;

    /// returns all spent outpoints from a provided list of outpoints at this height.
    /// We also pass the block_hash here, to make sure the block data still matches the expected
    /// block from get_block_data_for_range.
    async fn detect_spent_outpoints(
        &self,
        block_height: Height,
        block_hash: BlockHash,
        outpoints: HashSet<OutPoint>,
    ) -> Result<HashSet<OutPoint>>;

    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>>;
}

pub trait BlockData {
    fn blkheight(&self) -> Height;

    fn blkhash(&self) -> BlockHash;

    /// Checks if any of the outputs in the block matches the provided list of scriptpubkeys
    fn check_match_outputs(&self, candidate_spks: Vec<&[u8; 34]>) -> anyhow::Result<bool>;

    /// Check if any of the provided set in outpoints are spent in this block
    fn check_match_inputs(&self, owned_outpoints: &HashSet<OutPoint>) -> anyhow::Result<bool>;

    /// Fetch the transaction tweaks from this block.
    fn tweaks(&self) -> Vec<PublicKey>;
}
