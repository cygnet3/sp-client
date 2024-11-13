use std::collections::{HashMap, HashSet};

use bitcoin::{absolute::Height, BlockHash, OutPoint};

use anyhow::Result;

use crate::client::OwnedOutput;

pub trait Updater {
    /// Ask the updater to record the scanning progress.
    fn record_scan_progress(&mut self, start: Height, current: Height, end: Height) -> Result<()>;

    /// Ask the updater to record the outputs found in a block.
    fn record_block_outputs(
        &mut self,
        height: Height,
        blkhash: BlockHash,
        found_outputs: HashMap<OutPoint, OwnedOutput>,
    ) -> Result<()>;

    /// Ask the updater to record the inputs found in a block.
    fn record_block_inputs(
        &mut self,
        blkheight: Height,
        blkhash: BlockHash,
        found_inputs: HashSet<OutPoint>,
    ) -> Result<()>;

    /// Ask the updater to save all recorded changes to persistent storage.
    fn save_to_persistent_storage(&mut self) -> Result<()>;
}
