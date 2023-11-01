use bitcoin::secp256k1::Scalar;
use flutter_rust_bridge::StreamSink;

use crate::{
    constants::{LogEntry, ScanProgress, WalletStatus},
    db::{self},
    electrumclient::create_electrum_client,
    nakamotoclient,
    spclient::{self, get_birthday, get_sp_client},
    stream::{self, loginfo},
};

pub fn create_log_stream(s: StreamSink<LogEntry>) {
    stream::create_log_stream(s);
}
pub fn create_amount_stream(s: StreamSink<u32>) {
    stream::create_amount_stream(s);
}
pub fn create_scan_progress_stream(s: StreamSink<ScanProgress>) {
    stream::create_scan_progress_stream(s);
}

pub fn reset_wallet() {
    let birthday = get_birthday().unwrap();
    db::reset_scan_height(birthday).unwrap();
    db::drop_owned_outpoints().unwrap();
}

pub fn setup(files_dir: String) {
    loginfo("client setup");
    spclient::create_sp_client().unwrap();

    let birthday = get_birthday().unwrap();
    loginfo("db setup");
    db::setup(files_dir.clone(), birthday).unwrap();

    loginfo("db has been setup");

    nakamotoclient::setup(files_dir).unwrap();
    loginfo("nakamoto config has been setup");
}

pub fn start_nakamoto() {
    nakamotoclient::start_nakamoto_client().unwrap();
}

pub fn restart_nakamoto() {
    nakamotoclient::restart_nakamoto_client().unwrap();
}

pub fn get_peer_count() -> u32 {
    nakamotoclient::get_peer_count().unwrap()
}

pub fn scan_next_n_blocks(n: u32) {
    let sp_client = get_sp_client();

    let sp_receiver = &sp_client.sp_receiver;
    let scan_sk = sp_client.scan_privkey;

    let electrum_client = create_electrum_client().unwrap();

    let scan_key_scalar: Scalar = scan_sk.into();

    nakamotoclient::scan_blocks(n, sp_receiver, electrum_client, scan_key_scalar).unwrap();
}

pub fn scan_to_tip() {
    // 0 means scan to tip
    scan_next_n_blocks(0);
}

pub fn get_wallet_info() -> WalletStatus {
    let scanheight = db::get_scan_height().unwrap();
    let tip_height = nakamotoclient::get_tip().unwrap();
    let amount = get_amount();

    WalletStatus {
        amount,
        scan_height: scanheight,
        block_tip: tip_height,
    }
}

pub fn get_amount() -> u32 {
    db::get_sum_owned().unwrap()
}

pub fn get_receiving_address() -> String {
    let sp_address = spclient::get_receiving_address().unwrap();

    sp_address
}
