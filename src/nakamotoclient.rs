use std::{
    collections::HashMap, net,
    path::PathBuf,
    str::FromStr,
    sync::Mutex,
};

use anyhow::{Error, Result};
use bitcoin::{
    secp256k1::{PublicKey, Scalar, Secp256k1},
    util::bip158::BlockFilter,
    Block, BlockHash, Script, Transaction, TxOut, XOnlyPublicKey,
};
use electrum_client::ElectrumApi;
use lazy_static::lazy_static;
use nakamoto::{
    client::{self, traits::Handle, Client, Config},
    common::network::Services,
    net::poll::Waker,
};
use once_cell::sync::OnceCell;
use silentpayments::receiving::Receiver;

use crate::{
    constants::ScanProgress,
    db::{self, insert_outpoint, update_scan_height},
    stream::{loginfo, send_amount_update, send_scan_progress},
};

lazy_static! {
    static ref HANDLE: OnceCell<Mutex<nakamoto::client::Handle<nakamoto::net::poll::Waker>>> =
        OnceCell::new();
}

fn set_global_handle(handle: nakamoto::client::Handle<Waker>) {
    let _ = HANDLE.set(Mutex::new(handle));
}

pub fn get_tip() -> Result<u32> {
    let handle = HANDLE.get().unwrap().lock().unwrap();

    let res = handle.get_tip().unwrap();
    loginfo(format!("tip {}", res.0).as_str());

    Ok(res.0 as u32)
}

pub fn get_peer_count() -> Result<u32> {
    let handle = HANDLE.get().unwrap().lock().unwrap();

    let res = handle.get_peers(Services::default())?;

    loginfo(format!("peers {}", res.len()).as_str());

    Ok(res.len() as u32)
}

pub fn scan_blocks(
    mut n_blocks_to_scan: u32,
    sp_receiver: &Receiver,
    electrum_client: electrum_client::Client,
    scan_key_scalar: Scalar,
) -> anyhow::Result<()> {
    let handle = HANDLE.get().unwrap().lock().unwrap();

    loginfo("scanning blocks");

    let secp = Secp256k1::new();
    let filterchannel = handle.filters();
    let blkchannel = handle.blocks();

    let scan_height = db::get_scan_height()?;
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
        return Ok(());
    }

    loginfo(format!("start: {} end: {}", start, end).as_str());
    handle.request_filters(start as u64..=end as u64)?;

    let mut tweak_data_map = electrum_client.sp_tweaks(start as usize)?;

    for n in start..=end {
        if n % 10 == 0 || n == end {
            send_scan_progress(ScanProgress {
                start,
                current: n,
                end,
            });
        }

        let (blkfilter, blkhash, blkheight) = filterchannel.recv()?;

        let tweak_data_vec = tweak_data_map.remove(&(blkheight as u32));
        if let Some(tweak_data_vec) = tweak_data_vec {
            let tweak_data_vec: Result<Vec<PublicKey>> = tweak_data_vec
                .into_iter()
                .map(|x| PublicKey::from_str(&x).map_err(|x| Error::new(x)))
                .collect();
            let shared_secret_vec: Result<Vec<PublicKey>> = tweak_data_vec?
                .into_iter()
                .map(|x| {
                    x.mul_tweak(&secp, &scan_key_scalar)
                        .map_err(|x| Error::new(x))
                })
                .collect();
            let map = calculate_script_pubkeys(shared_secret_vec?, &sp_receiver);

            let found =
                search_filter_for_script_pubkeys(map.keys().cloned().collect(), blkfilter, blkhash);
            if found {
                handle.request_block(&blkhash)?;
                let (blk, _) = blkchannel.recv().unwrap();
                let res = scan_block(&sp_receiver, blk, map);

                loginfo(format!("outputs found:{:?}", res).as_str());

                for r in res {
                    insert_outpoint(blkheight, r.0, r.1)?;
                }
                let amount = db::get_sum_owned()?;
                send_amount_update(amount);
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
    update_scan_height(end).unwrap();
    Ok(())
}

pub fn start_nakamoto_client_and_set_handle(path: String) -> anyhow::Result<()> {
    let mut cfg = Config::new(client::Network::Signet);

    cfg.root = PathBuf::from(format!("{}/db", path));
    loginfo(format!("cfg.root = {:?}", cfg.root).as_str());

    // Create a client using the above network reactor.
    type Reactor = nakamoto::net::poll::Reactor<net::TcpStream>;
    let client = Client::<Reactor>::new()?;
    let handle = client.handle();

    set_global_handle(handle);

    loginfo("handle set");
    client.run(cfg).unwrap();
    panic!("this should never be reached");
}

// possible block has been found, scan the block
pub fn scan_block(
    sp_receiver: &Receiver,
    block: Block,
    mut map: HashMap<Script, PublicKey>,
) -> Vec<(u64, Script)> {
    let mut res: Vec<(u64, Script)> = vec![];

    for (_, tx) in block.txdata.into_iter().enumerate() {
        if !is_eligible_sp_transaction(&tx) {
            // println!("not a valid tx");
            continue;
        }
        // collect all taproot outputs from transaction
        // todo improve
        let mut outputs_map = get_tx_with_outpoints(&tx.output);

        if let (Some(tweak_data), scripts) =
            get_tx_taproot_scripts_and_tweak_data(tx.output, &mut map)
        {
            let xonlypubkeys = get_xonly_pubkeys_from_scripts(scripts);
            let outputs = sp_receiver
                .scan_transaction(&tweak_data, xonlypubkeys)
                .unwrap();
            for (output, _) in outputs {
                let txout = outputs_map.remove(&output).unwrap();

                let amt = txout.value;
                let script = txout.script_pubkey;

                res.push((amt, script));
            }
        }
    }

    res
}

fn is_eligible_sp_transaction(tx: &Transaction) -> bool {
    // we check if the output has a taproot output
    tx.output.iter().any(|x| x.script_pubkey.is_v1_p2tr())
}

fn get_xonly_pubkeys_from_scripts(scripts: Vec<Script>) -> Vec<XOnlyPublicKey> {
    scripts
        .into_iter()
        .map(|x| {
            if !x.is_v1_p2tr() {
                panic!("Only taproot allowed");
            }
            let output = x.into_bytes();
            XOnlyPublicKey::from_slice(&output[2..]).unwrap()
        })
        .collect()
}

fn get_tx_taproot_scripts_and_tweak_data(
    txout: Vec<TxOut>,
    map: &mut HashMap<Script, PublicKey>,
) -> (Option<PublicKey>, Vec<Script>) {
    let mut tweak_data = None;
    let outputs: Vec<Script> = txout
        .into_iter()
        .filter_map(|x| {
            let script = x.script_pubkey;

            if let Some(found_tweak_data) = map.remove(&script) {
                // this indicates we have found a tx with tweak data that we are looking for
                // in the minimal case, this output belongs to us, but there may be more
                tweak_data = Some(found_tweak_data);
                Some(script)
            } else if script.is_v1_p2tr() {
                Some(script)
            } else {
                None
            }
        })
        .collect();

    (tweak_data, outputs)
}

fn calculate_script_pubkeys(
    tweak_data_vec: Vec<PublicKey>,
    sp_receiver: &Receiver,
) -> HashMap<Script, PublicKey> {
    let mut res = HashMap::new();

    for tweak_data in tweak_data_vec {
        // using sp lib to get taproot output
        // we only need to look for the case n=0, we can look for the others if this matches
        let script_bytes = sp_receiver
            .get_script_bytes_from_shared_secret(&tweak_data)
            .unwrap();

        let script = Script::from(script_bytes.to_vec());
        res.insert(script, tweak_data);
    }
    res
}

fn get_tx_with_outpoints(txout: &Vec<TxOut>) -> HashMap<XOnlyPublicKey, TxOut> {
    let mut res = HashMap::new();

    for x in txout {
        let script = &x.script_pubkey;
        if script.is_v1_p2tr() {
            let output = script.clone().into_bytes();
            let pk = XOnlyPublicKey::from_slice(&output[2..]).unwrap();
            res.insert(pk, x.clone());
        }
    }
    res
}

fn search_filter_for_script_pubkeys(
    scriptpubkeys: Vec<Script>,
    blkfilter: BlockFilter,
    blkhash: BlockHash,
) -> bool {
    if scriptpubkeys.len() == 0 {
        return false;
    }

    // get bytes of every script
    let script_bytes: Vec<Vec<u8>> = scriptpubkeys.into_iter().map(|x| x.to_bytes()).collect();

    // the query for nakamoto filters is a iterator over the script byte slices
    let mut query = script_bytes.iter().map(|x| x.as_slice());

    // match our query against the block filter
    let found = blkfilter.match_any(&blkhash, &mut query).unwrap();

    found
}
