use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    sync::atomic::AtomicBool,
    time::Instant,
};

use anyhow::{Error, Result};
use bitcoin::{Amount, OutPoint, Txid, XOnlyPublicKey, absolute::Height, secp256k1::Scalar};
use futures::{Stream, StreamExt, pin_mut};
use log::info;
use silentpayments::{SharedSecret, receiving::Label};

use spdk_core::chain::{BoxedBlockData, ChainBackend, UtxoData};
use spdk_core::updater::{DiscoveredOutput, Updater};

use crate::client::SpClient;

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
        range: RangeInclusive<Height>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()> {
        info!(
            "start: {} end: {}",
            range.start().to_consensus_u32(),
            range.end().to_consensus_u32(),
        );
        let start_time: Instant = Instant::now();

        // get block data stream
        let block_data_stream =
            self.backend
                .get_block_data_for_range(range, dust_limit, with_cutthrough);

        // process blocks using block data stream
        self.process_blocks(block_data_stream).await?;

        // time elapsed for the scan
        info!(
            "Blindbit scan complete in {} seconds",
            start_time.elapsed().as_secs()
        );

        Ok(())
    }

    async fn process_blocks(
        &mut self,
        block_data_stream: impl Stream<Item = Result<BoxedBlockData>>,
    ) -> Result<()> {
        pin_mut!(block_data_stream);

        let mut tweak_count = 0;

        while let Some(blockdata) = block_data_stream.next().await {
            // stop scanning and return if interrupted
            if self.interrupt_requested() {
                break;
            }

            let blockdata = blockdata?;
            let blkhash = blockdata.blkhash();
            let blkheight = blockdata.blkheight();

            tweak_count += blockdata.tweaks().len();

            let (discovered_outputs, discovered_inputs) = self.process_block(&blockdata).await?;

            self.updater.record_block_scan_result(
                blkheight,
                blkhash,
                discovered_inputs,
                discovered_outputs,
            )?;
        }

        info!("Total number of tweaks processed: {tweak_count}");

        Ok(())
    }

    async fn process_block(
        &mut self,
        blockdata: &BoxedBlockData,
    ) -> Result<(HashMap<OutPoint, DiscoveredOutput>, HashSet<OutPoint>)> {
        let outs = self.process_block_outputs(blockdata).await?;

        // after processing outputs, we add the found outputs to our list
        self.owned_outpoints.extend(outs.keys());

        let ins = self.process_block_inputs(blockdata).await?;

        // after processing inputs, we remove the found inputs
        self.owned_outpoints.retain(|item| !ins.contains(item));

        Ok((outs, ins))
    }

    async fn process_block_outputs(
        &self,
        blockdata: &BoxedBlockData,
    ) -> Result<HashMap<OutPoint, DiscoveredOutput>> {
        let mut res = HashMap::new();

        let tweaks = blockdata.tweaks();

        if !tweaks.is_empty() {
            let secrets_map = self.client.script_to_secret_map(tweaks)?;

            //last_scan = last_scan.max(n as u32);
            let candidate_spks: Vec<&[u8; 34]> = secrets_map.keys().collect();

            let matched_outputs = blockdata.check_match_outputs(candidate_spks)?;

            //if match: fetch and scan utxos
            if matched_outputs {
                info!("matched outputs on: {}", blockdata.blkheight());
                let found = self.scan_utxos(blockdata.blkheight(), secrets_map).await?;

                if !found.is_empty() {
                    for (label, utxo, tweak) in found {
                        let outpoint = OutPoint {
                            txid: utxo.txid,
                            vout: utxo.vout,
                        };

                        let out = DiscoveredOutput {
                            tweak,
                            value: utxo.value,
                            script_pubkey: utxo.scriptpubkey,
                            label,
                        };

                        res.insert(outpoint, out);
                    }
                }
            }
        }
        Ok(res)
    }

    async fn process_block_inputs(&self, blockdata: &BoxedBlockData) -> Result<HashSet<OutPoint>> {
        let match_on_inputs = blockdata.check_match_inputs(&self.owned_outpoints)?;

        if match_on_inputs {
            // if match: return the set of all outpoints that have been spent this block
            info!("matched inputs on: {}", blockdata.blkheight());
            self.backend
                .detect_spent_outpoints(
                    blockdata.blkheight(),
                    blockdata.blkhash(),
                    self.owned_outpoints.clone(),
                )
                .await
        } else {
            // no match: return an empty set
            Ok(HashSet::new())
        }
    }

    async fn scan_utxos(
        &self,
        blkheight: Height,
        secrets_map: HashMap<[u8; 34], SharedSecret>,
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
                .scan_transaction(secret, &output_keys?)?;

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

    fn interrupt_requested(&self) -> bool {
        !self
            .keep_scanning
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
