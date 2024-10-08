use std::collections::{HashMap, HashSet};

use bitcoin::{absolute::Height, BlockHash, OutPoint};

use anyhow::Result;

use crate::client::OwnedOutput;

pub trait Updater {
    fn update_last_scan(&mut self, height: Height);

    fn send_scan_progress(&self, current: Height);

    fn record_block_outputs(
        &mut self,
        height: Height,
        found_outputs: HashMap<OutPoint, OwnedOutput>,
    );
    fn record_block_inputs(
        &mut self,
        blkheight: Height,
        blkhash: BlockHash,
        found_inputs: HashSet<OutPoint>,
    ) -> Result<()>;

    fn mark_mined(&mut self, outpoint: OutPoint, mined_in_block: BlockHash) -> Result<()>;

    fn revert_spent_status(&mut self, outpoint: OutPoint) -> Result<()>;
}
