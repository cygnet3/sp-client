use std::{ops::RangeInclusive, pin::Pin};

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{absolute::Height, Amount};
use futures::Stream;

use super::structs::{BlockData, SpentIndexData, UtxoData};

#[async_trait]
pub trait ChainBackend {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BlockData>> + Send>>;

    async fn spent_index(&self, block_height: Height) -> Result<SpentIndexData>;

    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>>;

    async fn block_height(&self) -> Result<Height>;
}
