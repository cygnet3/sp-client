use std::{
    collections::{HashMap, HashSet},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use anyhow::{bail, Error, Result};
use bitcoin::{
    absolute::Height,
    bip158::BlockFilter,
    hashes::{sha256, Hash},
    secp256k1::{PublicKey, Scalar},
    Amount, BlockHash, OutPoint, Txid, XOnlyPublicKey,
};
use futures::{pin_mut, Stream, StreamExt};
use log::info;
use silentpayments::receiving::Label;

use crate::{
    backend::{BlockData, ChainBackend, FilterData, UtxoData},
    client::{OutputSpendStatus, OwnedOutput, SpClient},
    updater::Updater,
};

pub struct SpScanner<'a> {
    updater: Box<dyn Updater + Sync + Send>,
    backend: Box<dyn ChainBackend + Sync + Send>,
    client: SpClient,
    keep_scanning: &'a AtomicBool,      // used to interrupt scanning
    owned_outpoints: HashSet<OutPoint>, // used to scan block inputs
}

impl<'a> SpScanner<'a> {
    pub fn new(
        client: SpClient,
        updater: Box<dyn Updater + Sync + Send>,
        backend: Box<dyn ChainBackend + Sync + Send>,
        owned_outpoints: HashSet<OutPoint>,
        keep_scanning: &'a AtomicBool,
    ) -> Self {
        Self {
            client,
            updater,
            backend,
            owned_outpoints,
            keep_scanning,
        }
    }

    pub async fn scan_blocks(
        &mut self,
        start: Height,
        end: Height,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()> {
        if start > end {
            bail!("bigger start than end: {} > {}", start, end);
        }

        info!("start: {} end: {}", start, end);
        let start_time: Instant = Instant::now();

        // get block data stream
        let range = start.to_consensus_u32()..=end.to_consensus_u32();
        let block_data_stream =
            self.backend
                .get_block_data_for_range(range, dust_limit, with_cutthrough);

        // process blocks using block data stream
        self.process_blocks(start, end, block_data_stream).await?;

        // time elapsed for the scan
        info!(
            "Blindbit scan complete in {} seconds",
            start_time.elapsed().as_secs()
        );

        Ok(())
    }

    async fn process_blocks(
        &mut self,
        start: Height,
        end: Height,
        block_data_stream: impl Stream<Item = Result<BlockData>>,
    ) -> Result<()> {
        pin_mut!(block_data_stream);

        let mut update_time: Instant = Instant::now();

        while let Some(blockdata) = block_data_stream.next().await {
            let blockdata = blockdata?;
            let blkheight = blockdata.blkheight;
            let blkhash = blockdata.blkhash;

            // stop scanning and return if interrupted
            if self.interrupt_requested() {
                self.updater.save_to_persistent_storage()?;
                return Ok(());
            }

            let mut save_to_storage = false;

            // always save on last block or after 30 seconds since last save
            if blkheight == end || update_time.elapsed() > Duration::from_secs(30) {
                save_to_storage = true;
            }

            let (found_outputs, found_inputs) = self.process_block(blockdata).await?;

            if !found_outputs.is_empty() {
                save_to_storage = true;
                self.updater
                    .record_block_outputs(blkheight, blkhash, found_outputs)?;
            }

            if !found_inputs.is_empty() {
                save_to_storage = true;
                self.updater
                    .record_block_inputs(blkheight, blkhash, found_inputs)?;
            }

            // tell the updater we scanned this block
            self.updater.record_scan_progress(start, blkheight, end)?;

            if save_to_storage {
                self.updater.save_to_persistent_storage()?;
                update_time = Instant::now();
            }
        }

        Ok(())
    }

    async fn process_block(
        &mut self,
        blockdata: BlockData,
    ) -> Result<(HashMap<OutPoint, OwnedOutput>, HashSet<OutPoint>)> {
        let BlockData {
            blkheight,
            tweaks,
            new_utxo_filter,
            spent_filter,
            ..
        } = blockdata;

        let outs = self
            .process_block_outputs(blkheight, tweaks, new_utxo_filter)
            .await?;

        // after processing outputs, we add the found outputs to our list
        self.owned_outpoints.extend(outs.keys());

        let ins = self.process_block_inputs(blkheight, spent_filter).await?;

        // after processing inputs, we remove the found inputs
        self.owned_outpoints.retain(|item| !ins.contains(item));

        Ok((outs, ins))
    }

    async fn process_block_outputs(
        &self,
        blkheight: Height,
        tweaks: Vec<PublicKey>,
        new_utxo_filter: FilterData,
    ) -> Result<HashMap<OutPoint, OwnedOutput>> {
        let mut res = HashMap::new();

        if !tweaks.is_empty() {
            let secrets_map = self.client.get_script_to_secret_map(tweaks)?;

            //last_scan = last_scan.max(n as u32);
            let candidate_spks: Vec<&[u8; 34]> = secrets_map.keys().collect();

            //get block gcs & check match
            let blkfilter = BlockFilter::new(&new_utxo_filter.data);
            let blkhash = new_utxo_filter.block_hash;

            let matched_outputs = Self::check_block_outputs(blkfilter, blkhash, candidate_spks)?;

            //if match: fetch and scan utxos
            if matched_outputs {
                info!("matched outputs on: {}", blkheight);
                let found = self.scan_utxos(blkheight, secrets_map).await?;

                if !found.is_empty() {
                    for (label, utxo, tweak) in found {
                        let outpoint = OutPoint {
                            txid: utxo.txid,
                            vout: utxo.vout,
                        };

                        let out = OwnedOutput {
                            blockheight: blkheight,
                            tweak: tweak.to_be_bytes(),
                            amount: utxo.value,
                            script: utxo.scriptpubkey,
                            label,
                            spend_status: OutputSpendStatus::Unspent,
                        };

                        res.insert(outpoint, out);
                    }
                }
            }
        }
        Ok(res)
    }

    async fn process_block_inputs(
        &self,
        blkheight: Height,
        spent_filter: FilterData,
    ) -> Result<HashSet<OutPoint>> {
        let mut res = HashSet::new();

        let blkhash = spent_filter.block_hash;

        // first get the 8-byte hashes used to construct the input filter
        let input_hashes_map = self.get_input_hashes(blkhash)?;

        // check against filter
        let blkfilter = BlockFilter::new(&spent_filter.data);
        let matched_inputs = self.check_block_inputs(
            blkfilter,
            blkhash,
            input_hashes_map.keys().cloned().collect(),
        )?;

        // if match: download spent data, collect the outpoints that are spent
        if matched_inputs {
            info!("matched inputs on: {}", blkheight);
            let spent = self.backend.spent_index(blkheight).await?.data;

            for spent in spent {
                let hex: &[u8] = spent.as_ref();

                if let Some(outpoint) = input_hashes_map.get(hex) {
                    res.insert(*outpoint);
                }
            }
        }
        Ok(res)
    }

    async fn scan_utxos(
        &self,
        blkheight: Height,
        secrets_map: HashMap<[u8; 34], PublicKey>,
    ) -> Result<Vec<(Option<Label>, UtxoData, Scalar)>> {
        let utxos = self.backend.utxos(blkheight).await?;

        let mut res: Vec<(Option<Label>, UtxoData, Scalar)> = vec![];

        // group utxos by the txid
        let mut txmap: HashMap<Txid, Vec<UtxoData>> = HashMap::new();
        for utxo in utxos {
            txmap.entry(utxo.txid).or_default().push(utxo);
        }

        for utxos in txmap.into_values() {
            // check if we know the secret to any of the spks
            let mut secret = None;
            for utxo in utxos.iter() {
                let spk = utxo.scriptpubkey.as_bytes();
                if let Some(s) = secrets_map.get(spk) {
                    secret = Some(s);
                    break;
                }
            }

            // skip this tx if no secret is found
            let secret = match secret {
                Some(secret) => secret,
                None => continue,
            };

            let output_keys: Result<Vec<XOnlyPublicKey>> = utxos
                .iter()
                .filter_map(|x| {
                    if x.scriptpubkey.is_p2tr() {
                        Some(
                            XOnlyPublicKey::from_slice(&x.scriptpubkey.as_bytes()[2..])
                                .map_err(Error::new),
                        )
                    } else {
                        None
                    }
                })
                .collect();

            let ours = self
                .client
                .sp_receiver
                .scan_transaction(secret, output_keys?)?;

            for utxo in utxos {
                if !utxo.scriptpubkey.is_p2tr() || utxo.spent {
                    continue;
                }

                match XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..]) {
                    Ok(xonly) => {
                        for (label, map) in ours.iter() {
                            if let Some(scalar) = map.get(&xonly) {
                                res.push((label.clone(), utxo, *scalar));
                                break;
                            }
                        }
                    }
                    Err(_) => todo!(),
                }
            }
        }

        Ok(res)
    }

    // Check if this block contains relevant transactions
    fn check_block_outputs(
        created_utxo_filter: BlockFilter,
        blkhash: BlockHash,
        candidate_spks: Vec<&[u8; 34]>,
    ) -> Result<bool> {
        // check output scripts
        let output_keys: Vec<_> = candidate_spks
            .into_iter()
            .map(|spk| spk[2..].as_ref())
            .collect();

        // note: match will always return true for an empty query!
        if !output_keys.is_empty() {
            Ok(created_utxo_filter.match_any(&blkhash, &mut output_keys.into_iter())?)
        } else {
            Ok(false)
        }
    }

    fn get_input_hashes(&self, blkhash: BlockHash) -> Result<HashMap<[u8; 8], OutPoint>> {
        let mut map: HashMap<[u8; 8], OutPoint> = HashMap::new();

        for outpoint in &self.owned_outpoints {
            let mut arr = [0u8; 68];
            arr[..32].copy_from_slice(&outpoint.txid.to_raw_hash().to_byte_array());
            arr[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
            arr[36..].copy_from_slice(&blkhash.to_byte_array());
            let hash = sha256::Hash::hash(&arr);

            let mut res = [0u8; 8];
            res.copy_from_slice(&hash[..8]);

            map.insert(res, outpoint.clone());
        }

        Ok(map)
    }

    // Check if this block contains relevant transactions
    fn check_block_inputs(
        &self,
        spent_filter: BlockFilter,
        blkhash: BlockHash,
        input_hashes: Vec<[u8; 8]>,
    ) -> Result<bool> {
        // note: match will always return true for an empty query!
        if !input_hashes.is_empty() {
            Ok(spent_filter.match_any(&blkhash, &mut input_hashes.into_iter())?)
        } else {
            Ok(false)
        }
    }

    fn interrupt_requested(&self) -> bool {
        !self
            .keep_scanning
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
