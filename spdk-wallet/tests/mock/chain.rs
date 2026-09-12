use anyhow::Result;
use backend_blindbit_v1::{
    api_structs::{FilterResponse, SpentIndexResponse, UtxoResponse},
    structs::BlindbitV1BlockData,
    utils::input_hashes_map,
};
use std::collections::HashSet;
use std::fs::File;
use std::ops::RangeInclusive;
use std::pin::Pin;

use async_trait::async_trait;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, BlockHash, OutPoint};
use futures::{Stream, stream};

use spdk_core::chain::{BoxedBlockData, ChainBackend, SpentIndexData, UtxoData};

const BLOCK_DATA_PATH: &str = "tests/resources/blocks";

pub struct MockChainBackend {}

#[async_trait]
impl ChainBackend for MockChainBackend {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<Height>,
        _dust_limit: Amount,
        _with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BoxedBlockData>> + Send>> {
        let range = range.start().to_consensus_u32()..=range.end().to_consensus_u32();

        let values = range.map(move |n| {
            let file = File::open(format!("{BLOCK_DATA_PATH}/{n}/tweaks.json")).unwrap();
            let tweaks: Vec<PublicKey> = serde_json::from_reader(file).unwrap();

            let file = File::open(format!("{BLOCK_DATA_PATH}/{n}/filter-new-utxos.json")).unwrap();
            let new_utxo_filter: FilterResponse = serde_json::from_reader(file).unwrap();

            let file = File::open(format!("{BLOCK_DATA_PATH}/{n}/filter-spent.json")).unwrap();
            let spent_filter: FilterResponse = serde_json::from_reader(file).unwrap();

            let blkhash = new_utxo_filter.block_hash;
            let blkheight = new_utxo_filter.block_height;

            Ok(Box::new(BlindbitV1BlockData {
                blkheight,
                blkhash,
                tweaks,
                new_utxo_filter: new_utxo_filter.into(),
                spent_filter: spent_filter.into(),
            }) as BoxedBlockData)
        });

        let stream = stream::iter(values);

        Box::pin(stream)
    }

    async fn detect_spent_outpoints(
        &self,
        block_height: Height,
        block_hash: BlockHash,
        outpoints: HashSet<OutPoint>,
    ) -> Result<HashSet<OutPoint>> {
        let file =
            File::open(format!("{BLOCK_DATA_PATH}/{block_height}/spent-index.json")).unwrap();
        let spent_index: SpentIndexResponse = serde_json::from_reader(file).unwrap();

        let index_data: SpentIndexData = spent_index.into();

        let hashes_to_outpoint = input_hashes_map(&outpoints, block_hash)?;

        let mut res = HashSet::new();

        for spent in index_data.data {
            let hex: &[u8] = spent.as_ref();
            if let Some(outpoint) = hashes_to_outpoint.get(hex) {
                res.insert(*outpoint);
            }
        }

        Ok(res)
    }

    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>> {
        let file = File::open(format!("{BLOCK_DATA_PATH}/{block_height}/utxos.json")).unwrap();
        let utxos: Vec<UtxoResponse> = serde_json::from_reader(file).unwrap();

        Ok(utxos.into_iter().map(Into::into).collect())
    }
}
