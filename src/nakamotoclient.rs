use std::{collections::HashMap, net, path::PathBuf, str::FromStr, sync::{atomic::{AtomicBool, Ordering}}, thread::{self, sleep, JoinHandle}, time::{Duration, Instant}};

use anyhow::{Error, Result};
use bitcoin::{
    secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
    Block, Script, TxOut, XOnlyPublicKey, OutPoint, network::constants::ServiceFlags,
};
use electrum_client::ElectrumApi;
use lazy_static::lazy_static;
use nakamoto::{
    client::{self, traits::Handle as _, Client, Config, Handle},
    common::network::Services,
    net::poll::Waker,
};
use once_cell::sync::OnceCell;
use silentpayments::receiving::Receiver;

use crate::{
    spclient::{OwnedOutput, ScanProgress, SpClient},
    stream::{loginfo, send_amount_update, send_scan_progress, send_sync_progress, send_nakamoto_run}, constants::SyncStatus, electrumclient,
};

const ORDERING: Ordering = Ordering::SeqCst;

lazy_static! {
    static ref NAKAMOTO_RUN: AtomicBool = AtomicBool::new(false);
    static ref NAKAMOTO_CONFIG: OnceCell<Config> = OnceCell::new();
}

pub fn setup(network: String, path: String) -> Result<()> {
    let mut cfg = Config::new(client::Network::from_str(&network)
        .map_err(|_| Error::msg("Invalid network"))?);

    cfg.root = PathBuf::from(format!("{}/db", path));
    loginfo(format!("cfg.root = {:?}", cfg.root).as_str());

    match NAKAMOTO_CONFIG.set(cfg) {
        Ok(_) => (),
        Err(_) => { loginfo("NAKAMOTO_CONFIG already set"); }
    }
    Ok(())
}

pub fn start_nakamoto_client() -> Result<(Handle<Waker>, JoinHandle<()>)> {
    if let Err(_) = NAKAMOTO_RUN.compare_exchange(false, true, ORDERING, ORDERING) {
        return Err(Error::msg("Nakamoto client is already running"));
    }

    send_nakamoto_run(NAKAMOTO_RUN.load(ORDERING));

    let cfg = NAKAMOTO_CONFIG.wait().clone();
    // Create a client using the above network reactor.
    type Reactor = nakamoto::net::poll::Reactor<net::TcpStream>;
    let client = Client::<Reactor>::new()?;
    let handle = client.handle();
    
    let join_handle = thread::spawn(|| {
        client.run(cfg).unwrap();
    });

    Ok((handle, join_handle))
}

pub fn stop_nakamoto_client(handle: Handle<Waker>, join_handle: JoinHandle<()>) -> Result<()> {
    NAKAMOTO_RUN.store(false, ORDERING);
    send_nakamoto_run(NAKAMOTO_RUN.load(ORDERING));
    handle.shutdown()?;
    join_handle.join().map_err(|e| Error::msg("Failed to join thread"))?;
    Ok(())
}
pub fn sync_blockchain(mut handle: Handle<Waker>) -> Result<()> {
    handle.set_timeout(Duration::from_secs(10));

    if let Err(_) = handle.wait_for_peers(1, ServiceFlags::NETWORK) {
        return Err(Error::msg("Can't connect to peers"));
    } 

    let mut last_height = 0;

    loop {
        let peer_count = handle.get_peers(ServiceFlags::NETWORK)?;
        if peer_count.len() == 0 { continue };
        let (height, header, _) = handle.get_tip()?;
        send_sync_progress(SyncStatus {
            peer_count: peer_count.len() as u32,
            blockheight: height,
            bestblockhash: header.block_hash().to_string()
        });
        if last_height == 0 || last_height < height {
            last_height = height;
            sleep(Duration::from_secs(2));
            continue;
        }
        break;
    }

    Ok(())
pub fn get_tip() -> Result<u32> {
    let handle = get_global_handle()?;

    let res = handle.get_tip()?;
    loginfo(format!("tip {}", res.0).as_str());

    Ok(res.0 as u32)
}

pub fn get_peer_count() -> Result<u32> {
    let handle = get_global_handle()?;

    let res = handle.get_peers(Services::default())?;

    loginfo(format!("peers {}", res.len()).as_str());

    Ok(res.len() as u32)
}

pub fn scan_blocks(
    mut handle: Handle<Waker>,
    mut n_blocks_to_scan: u32,
    mut sp_client: SpClient,
) -> anyhow::Result<()> {
    let electrum_client = electrumclient::create_electrum_client()?;

    handle.set_timeout(Duration::from_secs(10));

    if let Err(_) = handle.wait_for_peers(1, ServiceFlags::COMPACT_FILTERS) {
        return Err(Error::msg("Can't find peers with compact filters service"));
    } 

    loginfo("scanning blocks");

    let secp = Secp256k1::new();
    let filterchannel = handle.filters();
    let blkchannel = handle.blocks();

    let scan_height = sp_client.last_scan;
    let tip_height = handle.get_tip()?.0 as u32;

    // 0 means scan to tip
    if n_blocks_to_scan == 0 {
        n_blocks_to_scan = tip_height - scan_height;
    }

    loginfo(format!("scan_height: {:?}", scan_height).as_str());

    let start = scan_height + 1;
    let end = if scan_height + n_blocks_to_scan <= tip_height {
        scan_height + n_blocks_to_scan
    } else {
        tip_height
    };

    if start > end {
        return Err(Error::msg("Start height can't be higher than end"));
    }

    loginfo(format!("start: {} end: {}", start, end).as_str());
    handle.request_filters(start as u64..=end as u64)?;

    let mut tweak_data_map = electrum_client.sp_tweaks(start as usize)?;

    let scan_key_scalar = Scalar::from(sp_client.get_scan_key());
    let sp_receiver = sp_client.sp_receiver.clone();
    let start_time = Instant::now();

    for n in start..=end {
        if n % 10 == 0 || n == end {
            send_scan_progress(ScanProgress {
                start,
                current: n,
                end,
            });
        }

        let (blkfilter, blkhash, blkheight) = filterchannel.recv()?;

        if let Some(tweak_data_vec) = tweak_data_map.remove(&(blkheight as u32)) {
            let shared_secrets: Result<Vec<PublicKey>> = tweak_data_vec
                .into_iter()
                .map(|s| {
                    let x = PublicKey::from_str(&s).map_err(|e| Error::new(e))?;
                    x.mul_tweak(&secp, &scan_key_scalar)
                        .map_err(|e| Error::new(e))
                })
                .collect();
            let shared_secrets = shared_secrets?;

            let candidate_spks: Result<Vec<Script>, _> = shared_secrets
                .iter()
                .map(|s| {
                    sp_receiver
                        .get_script_bytes_from_shared_secret(s)
                        .map(|bytes| Script::from(bytes.to_vec()))
                })
                .collect();
            let candidate_spks = candidate_spks?;

            let found = blkfilter.match_any(&blkhash, &mut candidate_spks.iter().map(|spk| spk.as_bytes()))?;
            if found {
                handle.request_block(&blkhash)?;
                let (blk, _) = blkchannel.recv()?;
                let owned = scan_block(&sp_receiver, blk, candidate_spks.into_iter().zip(shared_secrets).collect())?;

                sp_client.extend_owned(owned);

                send_amount_update(sp_client.get_total_amt());

                send_scan_progress(ScanProgress {
                    start,
                    current: n,
                    end,
                });
            } else {
                // println!("no payments found");
            }
        } else {
            // println!("no tweak data for this block");
        }
    }

    // time elapsed for the scan
    loginfo(&format!("Scan complete in {} seconds", start_time.elapsed().as_secs()));

    // update last_scan height
    sp_client.update_last_scan(end);
    sp_client.save_to_disk()
}

// possible block has been found, scan the block
fn scan_block(
    sp_receiver: &Receiver,
    block: Block,
    spk2secret: HashMap<Script, PublicKey>,
) -> Result<Vec<OwnedOutput>> {
    let blkheight = block.bip34_block_height()?;
    let mut res: Vec<OwnedOutput> = vec![];

    for tx in block.txdata.into_iter() {
        let txid = tx.txid();

        // collect all taproot outputs from transaction
        let p2tr_outs: Vec<(usize, TxOut)> = tx.output
            .into_iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey.is_v1_p2tr())
            .collect();

        if p2tr_outs.is_empty() { continue }; // no taproot output

        let mut secret: Option<PublicKey> = None;
        // Does this transaction contains one of the outputs we already found?
        for spk in p2tr_outs.iter().map(|(_, o)| &o.script_pubkey) {
            if let Some(s) = spk2secret.get(spk) {
                // we might have at least one output in this transaction
                secret = Some(*s);
                break;
            }
        }

        if secret.is_none() { continue }; // we don't have a secret that matches any of the keys

        // Now we can just run sp_receiver on all the p2tr outputs
        let xonlykeys: Result<Vec<XOnlyPublicKey>> = p2tr_outs
            .iter()
            .map(|(_, o)| {
                XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..])
                    .map_err(|e| Error::new(e))
            })
            .collect();

        let ours = sp_receiver.scan_transaction(&secret.unwrap(), xonlykeys?)?;
        res.extend(p2tr_outs.iter().filter_map(|(i, o)| {
            match XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]) {
                Ok(key) => {
                    if let Some(scalar) = ours.get(&key) {
                        match SecretKey::from_slice(&scalar.to_be_bytes()) {
                            Ok(tweak) => Some(OwnedOutput {
                                txoutpoint: OutPoint { txid, vout: *i as u32 }.to_string(),
                                blockheight: blkheight as u32,
                                tweak: hex::encode(tweak.secret_bytes()),
                                amount: o.value,
                                script: hex::encode(o.script_pubkey.as_bytes()),
                                spent: false,
                                spent_by: None,
                            }),
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }));

    }

    Ok(res)
}
