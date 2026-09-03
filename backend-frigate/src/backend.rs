use anyhow::Result;
use std::{ops::RangeInclusive, pin::Pin};

use crate::client::FrigateClient;
use async_trait::async_trait;
use bitcoin::{Amount, absolute::Height};
use futures::{Stream, StreamExt, stream};
use spdk_core::chain::{BlockData, ChainBackend, SpentIndexData, UtxoData};

pub struct FrigateBackend {
    client: FrigateClient,
}

impl FrigateBackend {
    pub fn new(client: FrigateClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ChainBackend for FrigateBackend {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<Height>,
        reverse: bool,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BlockData>> + Send>> {
        todo!()
    }

    async fn spent_index(&self, block_height: Height) -> Result<SpentIndexData> {
        todo!()
    }

    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>> {
        todo!()
    }
}
