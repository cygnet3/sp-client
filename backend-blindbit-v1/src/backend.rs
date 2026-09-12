use std::{collections::HashSet, ops::RangeInclusive, pin::Pin};

use anyhow::{Result, bail};
use async_trait::async_trait;
use bitcoin::{Amount, BlockHash, OutPoint, absolute::Height};
use futures::{Stream, StreamExt, stream};

use spdk_core::chain::{BoxedBlockData, ChainBackend, SpentIndexData, UtxoData};

use crate::{BlindbitClient, structs::BlindbitV1BlockData, utils::input_hashes_map};

const CONCURRENT_FILTER_REQUESTS: usize = 200;

#[derive(Debug)]
pub struct BlindbitBackend {
    client: BlindbitClient,
}

impl BlindbitBackend {
    pub fn new(client: BlindbitClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ChainBackend for BlindbitBackend {
    /// High-level function to get block data for a range of blocks.
    /// Block data includes all the information needed to determine if a block is relevant for scanning,
    /// but does not include utxos, or spent index.
    /// These need to be fetched separately afterwards, if it is determined this block is relevant.
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<Height>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BoxedBlockData>> + Send>> {
        let client = self.client.clone();

        // convert range to u32 since Height does not implement Step
        let range = range.start().to_consensus_u32()..=range.end().to_consensus_u32();

        let res = stream::iter(range)
            .map(move |n| {
                let client = client.clone();

                async move {
                    let blkheight = Height::from_consensus(n)?;
                    let tweaks = match with_cutthrough {
                        true => client.tweaks(blkheight, dust_limit).await?,
                        false => client.tweak_index(blkheight, dust_limit).await?,
                    };
                    let new_utxo_filter = client.filter_new_utxos(blkheight).await?;
                    let spent_filter = client.filter_spent(blkheight).await?;
                    let blkhash = new_utxo_filter.block_hash;
                    Ok(Box::new(BlindbitV1BlockData {
                        blkheight,
                        blkhash,
                        tweaks,
                        new_utxo_filter: new_utxo_filter.into(),
                        spent_filter: spent_filter.into(),
                    }) as BoxedBlockData)
                }
            })
            .buffered(CONCURRENT_FILTER_REQUESTS);

        Box::pin(res)
    }

    async fn detect_spent_outpoints(
        &self,
        block_height: Height,
        block_hash: BlockHash,
        outpoints: HashSet<OutPoint>,
    ) -> Result<HashSet<OutPoint>> {
        let response = self.client.spent_index(block_height).await?;
        if block_hash != response.block_hash {
            bail!("Mismatched block hash");
        }

        let index_data: SpentIndexData = response.into();

        let input_hashes_map = input_hashes_map(&outpoints, block_hash)?;

        let mut res = HashSet::new();

        for spent in index_data.data {
            let hex: &[u8] = spent.as_ref();
            if let Some(outpoint) = input_hashes_map.get(hex) {
                res.insert(*outpoint);
            }
        }

        Ok(res)
    }

    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>> {
        Ok(self
            .client
            .utxos(block_height)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}
