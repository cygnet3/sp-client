use std::{ops::RangeInclusive, pin::Pin};

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::{absolute::Height, Amount};
use futures::{stream, Stream, StreamExt};

use anyhow::Result;

use crate::{backend::blindbit::BlindbitClient, BlockData, SpentIndexData, UtxoData};

#[cfg(not(target_arch = "wasm32"))]
use crate::backend::ChainBackend;

#[cfg(target_arch = "wasm32")]
use crate::backend::ChainBackendWasm;

const CONCURRENT_FILTER_REQUESTS: usize = 200;

#[derive(Debug)]
pub struct BlindbitBackend {
    client: BlindbitClient,
}

impl BlindbitBackend {
    pub fn new(blindbit_url: String) -> Result<Self> {
        Ok(Self {
            client: BlindbitClient::new(blindbit_url)?,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl ChainBackend for BlindbitBackend {
    /// High-level function to get block data for a range of blocks.
    /// Block data includes all the information needed to determine if a block is relevant for scanning,
    /// but does not include utxos, or spent index.
    /// These need to be fetched separately afterwards, if it is determined this block is relevant.
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BlockData>> + Send>> {
        let client = Arc::new(self.client.clone());

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
                    Ok(BlockData {
                        blkheight,
                        blkhash,
                        tweaks,
                        new_utxo_filter: new_utxo_filter.into(),
                        spent_filter: spent_filter.into(),
                    })
                }
            })
            .buffered(CONCURRENT_FILTER_REQUESTS);

        Box::pin(res)
    }

    async fn spent_index(&self, block_height: Height) -> Result<SpentIndexData> {
        self.client.spent_index(block_height).await.map(Into::into)
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

    async fn block_height(&self) -> Result<Height> {
        self.client.block_height().await
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl ChainBackendWasm for BlindbitBackend {
    /// High-level function to get block data for a range of blocks.
    /// Block data includes all the information needed to determine if a block is relevant for scanning,
    /// but does not include utxos, or spent index.
    /// These need to be fetched separately afterwards, if it is determined this block is relevant.
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BlockData>>>> {
        // For WASM, we need to avoid Arc and use a different approach
        // Since WASM doesn't support threading well, we'll use a simpler approach
        let client = self.client.clone();
        
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
                    Ok(BlockData {
                        blkheight,
                        blkhash,
                        tweaks,
                        new_utxo_filter: new_utxo_filter.into(),
                        spent_filter: spent_filter.into(),
                    })
                }
            })
            .buffered(1); // Use buffered(1) for WASM to avoid concurrency issues

        Box::pin(res)
    }

    async fn spent_index(&self, block_height: Height) -> Result<SpentIndexData> {
        self.client.spent_index(block_height).await.map(Into::into)
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

    async fn block_height(&self) -> Result<Height> {
        self.client.block_height().await
    }
}
