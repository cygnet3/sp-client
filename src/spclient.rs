use bip39::Mnemonic;
use bitcoin::{
    secp256k1::{Secp256k1, SecretKey, ONE_KEY},
    util::bip32::{DerivationPath, ExtendedPrivKey},
    Network, OutPoint, Script, Txid,
};
use serde::{Serialize, Deserialize};
use silentpayments::receiving::Receiver;
use std::str::FromStr;

use anyhow::Result;

use crate::db::FileWriter;

pub struct ScanProgress {
    pub start: u32,
    pub current: u32,
    pub end: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OwnedOutput {
    pub txoutpoint: OutPoint, 
    pub blockheight: u32,
    pub tweak: String,
    pub amount: u64,
    pub script: Script,
    pub spent: bool,
    pub spent_by: Option<Txid>
}


#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SpClient {
    pub label: String,
    scan_sk: SecretKey,
    spend_sk: SecretKey,
    pub sp_receiver: Receiver,
    pub birthday: u32,
    pub last_scan: u32,
    pub total_amt: u64,
    owned: Vec<OwnedOutput>,
    writer: FileWriter,
}

impl SpClient {
    pub fn new(
        label: String,
        scan_sk: SecretKey,
        spend_sk: SecretKey,
        birthday: u32,
        is_testnet: bool,
        path: String,
    ) -> Result<Self> {
        let secp = Secp256k1::signing_only();
        let scan_pubkey = scan_sk.public_key(&secp);
        let spend_pubkey = spend_sk.public_key(&secp);
        let sp_receiver = Receiver::new(0, scan_pubkey, spend_pubkey, is_testnet)?;
        let writer = FileWriter::new(path, label.clone())?;

        Ok(Self {
            label,
            scan_sk,
            sp_receiver,
            birthday,
            last_scan: birthday,
            total_amt: 0,
            owned: vec![],
            spend_sk,
            writer
        })
    }

    pub fn try_init_from_disk(label: String, path: String) -> Result<SpClient> {
        let empty = SpClient::new(
            label,
            ONE_KEY,
            ONE_KEY,
            0,
            false,
            path,
        )?;

        empty.retrieve_from_disk()
    }

    pub fn update_last_scan(&mut self, scan_height: u32) {
        self.last_scan = scan_height;
    }

    pub fn get_total_amt(&mut self) -> u64 {
        self.total_amt = self.owned.iter()
            .filter(|x| !x.spent)
            .fold(0, |acc, x| acc + x.amount);
        self.total_amt
    }

    pub fn extend_owned(&mut self, owned: Vec<OwnedOutput>) {
        self.owned.extend(owned.into_iter());
    }

    pub fn list_outpoints(&self) -> Vec<OwnedOutput> {
        self.owned.clone()
    }

    pub fn reset_from_blockheight(self, blockheight: u32) -> Self {
        let mut new = self.clone();
        new.owned = vec![];
        new.owned = self.owned.into_iter()
            .filter(|o| o.blockheight <= blockheight)
            .collect();
        new.last_scan = blockheight;
        new.get_total_amt();

        new
    }

    pub fn save_to_disk(&self) -> Result<()> {
        self.writer.write_to_file(self)
    }

    pub fn retrieve_from_disk(self) -> Result<Self> {
        self.writer.read_from_file()
    }

    pub fn get_receiving_address(&self) -> String {
        self.sp_receiver.get_receiving_address()
    }
    
    pub fn get_scan_key(&self) -> SecretKey {
        self.scan_sk.clone()
    }
}

pub fn derive_keys_from_mnemonic(
    seedphrase: &str,
    passphrase: &str,
    is_testnet: bool,
) -> Result<(SecretKey, SecretKey)> {
    let mnemonic = Mnemonic::parse(seedphrase)?;
    let seed = mnemonic.to_seed(passphrase);

    let network = if is_testnet { Network::Testnet } else { Network::Bitcoin };

    let xprv = ExtendedPrivKey::new_master(network, &seed)?;

    derive_keys_from_xprv(xprv)
}

fn derive_keys_from_xprv(xprv: ExtendedPrivKey) -> Result<(SecretKey, SecretKey)> {
    let (scan_path, spend_path) = match xprv.network {
        bitcoin::Network::Bitcoin => ("m/352h/0h/0h/1h/0", "m/352h/0h/0h/0h/0"),
        _ => ("m/352h/1h/0h/1h/0", "m/352h/1h/0h/0h/0"),
    };

    let secp = Secp256k1::signing_only();
    let scan_path = DerivationPath::from_str(scan_path)?;
    let spend_path = DerivationPath::from_str(spend_path)?;
    let scan_privkey = xprv.derive_priv(&secp, &scan_path)?.private_key;
    let spend_privkey = xprv.derive_priv(&secp, &spend_path)?.private_key;

    Ok((scan_privkey, spend_privkey))
}
