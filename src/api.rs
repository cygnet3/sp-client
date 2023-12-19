use std::str::FromStr;

use bitcoin::secp256k1::Scalar;
use flutter_rust_bridge::StreamSink;

use crate::{
    constants::{LogEntry, ScanProgress, WalletStatus, WalletType},
    db::{self},
    electrumclient::create_electrum_client,
    nakamotoclient,
    spclient::{self, get_sp_client, derive_keys_from_mnemonic},
    stream::{self, loginfo},
};

const PASSPHRASE: &str = ""; // no passphrase for now

pub fn create_log_stream(s: StreamSink<LogEntry>) {
    stream::create_log_stream(s);
}
pub fn create_amount_stream(s: StreamSink<u32>) {
    stream::create_amount_stream(s);
}
pub fn create_scan_progress_stream(s: StreamSink<ScanProgress>) {
    stream::create_scan_progress_stream(s);
}

pub fn setup(
    files_dir: String,
    wallet_type: WalletType,
    birthday: u32,
    is_testnet: bool,
) -> Result<(), String> {
    match wallet_type {
        WalletType::Mnemonic(mnemonic) => {
            let (scan_sk, spend_sk) = derive_keys_from_mnemonic(&mnemonic, PASSPHRASE, is_testnet)
                .map_err(|e| e.to_string())?;
            spclient::create_sp_client(scan_sk, spend_sk, birthday, is_testnet)
                .map_err(|e| e.to_string())?;
        },
        WalletType::PrivateKeys((scan_sk_hex, spend_sk_hex)) => {
            let scan_sk = bitcoin::secp256k1::SecretKey::from_str(&scan_sk_hex)
                .map_err(|e| e.to_string())?;
            let spend_sk = bitcoin::secp256k1::SecretKey::from_str(&spend_sk_hex)
                .map_err(|e| e.to_string())?;
            spclient::create_sp_client(scan_sk, spend_sk, birthday, is_testnet)
                .map_err(|e| e.to_string())?;
        },
        WalletType::ReadOnly(_) => return Err("readonly not yet implemented".into()),
    };

    loginfo("sp client has been setup");

    db::setup(files_dir.clone(), birthday)
        .map_err(|e| e.to_string())?;
    loginfo("db has been setup");

    nakamotoclient::setup(files_dir);
    loginfo("nakamoto config has been setup");

    Ok(())
}


pub fn reset_wallet() -> Result<(), String> {
    let birthday = spclient::get_birthday();
    db::reset_scan_height(birthday)
        .map_err(|e| e.to_string())?;
    db::drop_owned_outpoints()
        .map_err(|e| e.to_string())?;

    Ok(())
}

pub fn start_nakamoto() -> Result<(), String> {
    nakamotoclient::start_nakamoto_client()
        .map_err(|e| e.to_string())
}

pub fn restart_nakamoto() -> Result<(), String> {
    nakamotoclient::restart_nakamoto_client()
        .map_err(|e| e.to_string())
}

pub fn get_peer_count() -> Result<u32, String> {
    nakamotoclient::get_peer_count()
        .map_err(|e| e.to_string())
}

pub fn scan_next_n_blocks(n: u32) -> Result<(), String> {
    let sp_client = get_sp_client();

    let sp_receiver = &sp_client.sp_receiver;
    let scan_sk = sp_client.scan_sk;

    let electrum_client = create_electrum_client()
        .map_err(|e| e.to_string())?;

    let scan_key_scalar: Scalar = scan_sk.into();

    nakamotoclient::scan_blocks(n, sp_receiver, electrum_client, scan_key_scalar)
        .map_err(|e| e.to_string())
}

pub fn scan_to_tip() -> Result<(), String> {
    // 0 means scan to tip
    scan_next_n_blocks(0)
}

pub fn get_wallet_info() -> Result<WalletStatus, String> {
    let scanheight = db::get_scan_height()
        .map_err(|e| e.to_string())?;
    let tip_height = nakamotoclient::get_tip()
        .map_err(|e| e.to_string())?;
    let amount = get_wallet_balance()?;

    Ok(WalletStatus {
        amount,
        scan_height: scanheight,
        block_tip: tip_height,
    })
}

pub fn get_birthday() -> u32 {
    spclient::get_birthday()
}

pub fn get_wallet_balance() -> Result<u32, String> {
    db::get_sum_owned()
        .map_err(|e| e.to_string())
}

pub fn get_receiving_address() -> Result<String, String> {
    spclient::get_receiving_address().map_err(|e| e.to_string())
}
