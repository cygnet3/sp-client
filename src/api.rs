use std::str::FromStr;

use flutter_rust_bridge::StreamSink;

use crate::{
    constants::{LogEntry, WalletType},
    electrumclient::create_electrum_client,
    nakamotoclient,
    spclient::{ScanProgress, SpClient, derive_keys_from_mnemonic, SpendKey},
    stream::{self},
};

const PASSPHRASE: &str = ""; // no passphrase for now

pub struct WalletStatus {
    pub amount: u64,
    pub birthday: u32,
    pub scan_height: u32,
    pub tip_height: u32,
}

pub fn create_log_stream(s: StreamSink<LogEntry>) {
    stream::create_log_stream(s);
}
pub fn create_amount_stream(s: StreamSink<u64>) {
    stream::create_amount_stream(s);
}
pub fn create_scan_progress_stream(s: StreamSink<ScanProgress>) {
    stream::create_scan_progress_stream(s);
}

pub fn wallet_exists(label: String, files_dir: String) -> bool {
    match SpClient::try_init_from_disk(label, files_dir) {
        Ok(_) => true,
        Err(_) => false
    }
}

pub fn setup(
    label: String,
    files_dir: String,
    wallet_type: WalletType,
    birthday: u32,
    is_testnet: bool,
) -> Result<String, String> {
    if wallet_exists(label.clone(), files_dir.clone()) { return Err(label) }; // If the wallet already exists we just send the label as an error message

    // TODO lot of repetition here
    match wallet_type {
        WalletType::New => {
            // We create a new wallet and return the new mnemonic
            let (mnemonic, scan_sk, spend_sk) = derive_keys_from_mnemonic("", PASSPHRASE, is_testnet)
                .map_err(|e| e.to_string())?;
            let sp_client = SpClient::new(label, scan_sk, SpendKey::Secret(spend_sk), birthday, is_testnet, files_dir)
                .map_err(|e| e.to_string())?;
            sp_client.save_to_disk()
                .map_err(|e| e.to_string())?;
            return Ok(mnemonic.to_string());
        },
        WalletType::Mnemonic(mnemonic) => {
            // We restore from seed
            let (_, scan_sk, spend_sk) = derive_keys_from_mnemonic(&mnemonic, PASSPHRASE, is_testnet)
                .map_err(|e| e.to_string())?;
            let sp_client = SpClient::new(label, scan_sk, SpendKey::Secret(spend_sk), birthday, is_testnet, files_dir)
                .map_err(|e| e.to_string())?;
            sp_client.save_to_disk()
                .map_err(|e| e.to_string())?;
            return Ok("".to_owned());
        },
        WalletType::PrivateKeys(scan_sk_hex, spend_sk_hex) => {
            // We directly restore with the keys
            let scan_sk = bitcoin::secp256k1::SecretKey::from_str(&scan_sk_hex)
                .map_err(|e| e.to_string())?;
            let spend_sk = bitcoin::secp256k1::SecretKey::from_str(&spend_sk_hex)
                .map_err(|e| e.to_string())?;
            let sp_client = SpClient::new(label, scan_sk, SpendKey::Secret(spend_sk), birthday, is_testnet, files_dir)
                .map_err(|e| e.to_string())?;
            sp_client.save_to_disk()
                .map_err(|e| e.to_string())?;
            return Ok("".to_owned());
        },
        WalletType::ReadOnly(scan_sk_hex, spend_pk_hex) => {
            // We're only able to find payments but not to spend it
            let scan_sk = bitcoin::secp256k1::SecretKey::from_str(&scan_sk_hex)
                .map_err(|e| e.to_string())?;
            let spend_pk = bitcoin::secp256k1::PublicKey::from_str(&spend_pk_hex)
                .map_err(|e| e.to_string())?;
            let sp_client = SpClient::new(label, scan_sk, SpendKey::Public(spend_pk), birthday, is_testnet, files_dir)
                .map_err(|e| e.to_string())?;
            sp_client.save_to_disk()
                .map_err(|e| e.to_string())?;
            return Ok("".to_owned());

        }
    };
}

/// Reset the last_scan of the wallet to its birthday, removing all outpoints
pub fn reset_wallet(path: String, label: String) -> Result<(), String> {
    match SpClient::try_init_from_disk(label, path) {
        Ok(sp_client) => {
            let birthday = sp_client.birthday;
            let new = sp_client.reset_from_blockheight(birthday);
            new.save_to_disk()
                .map_err(|e| e.to_string())
        },
        Err(_) => return Err("Wallet doesn't exist".to_owned()),
    }
}

pub fn remove_wallet(path: String, label: String) -> Result<(), String> {
    match SpClient::try_init_from_disk(label, path) {
        Ok(sp_client) => {
            sp_client.delete_from_disk().map_err(|e| e.to_string())
        },
        Err(_) => return Err("Wallet doesn't exist".to_owned()),
    }
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

pub fn scan_next_n_blocks(path: String, label: String, n: u32) -> Result<(), String> {
    let electrum_client = create_electrum_client()
        .map_err(|e| e.to_string())?;

    match SpClient::try_init_from_disk(label, path) {
        Ok(sp_client) => nakamotoclient::scan_blocks(n, sp_client, electrum_client).map_err(|e| e.to_string())?,
        Err(_) => return Err("Wallet not found".to_owned())
    }
    Ok(())
}

pub fn scan_to_tip(path: String, label: String) -> Result<(), String> {
    // 0 means scan to tip
    scan_next_n_blocks(path, label, 0)
}

pub fn get_wallet_info(path: String, label: String) -> Result<WalletStatus, String> {
    let sp_client = match SpClient::try_init_from_disk(label, path) {
        Ok(s) => s,
        Err(_) => return Err("Wallet not found".to_owned())
    };

    let scan_height = sp_client.last_scan;
    let birthday = sp_client.birthday;
    let tip_height = nakamotoclient::get_tip()
        .map_err(|e| e.to_string())?;
    let amount = sp_client.get_total_amt();

    Ok(WalletStatus {
        amount,
        birthday,
        scan_height,
        tip_height,
    })
}

pub fn get_receiving_address(path: String, label: String) -> Result<String, String> {
    let sp_client: SpClient;
    match SpClient::try_init_from_disk(label, path) {
        Ok(s) => sp_client = s,
        Err(_) => return Err("Wallet not found".to_owned())
    }

    Ok(sp_client.get_receiving_address())
}
