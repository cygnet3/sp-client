use bip39::Mnemonic;
use bitcoin::{bip32::{DerivationPath, Xpriv}, secp256k1::{constants::SECRET_KEY_SIZE, PublicKey, Secp256k1, SecretKey}, Network};
use nakamoto::common::bitcoin::OutPoint;
use serde::{Serialize, Deserialize};
use serde_with::serde_as;
use serde_with::DisplayFromStr;
use silentpayments::receiving::Receiver;
use std::{str::FromStr, collections::HashMap};

use anyhow::Result;

use crate::{db::FileWriter, stream::loginfo};

pub struct ScanProgress {
    pub start: u32,
    pub current: u32,
    pub end: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OwnedOutput {
    pub txoutpoint: String, 
    pub blockheight: u32,
    pub tweak: String,
    pub amount: u64,
    pub script: String,
    pub spent: bool,
    pub spent_by: Option<String>
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum SpendKey {
    Secret(SecretKey),
    Public(PublicKey)
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SpClient {
    pub label: String,
    scan_sk: SecretKey,
    spend_key: SpendKey,
    pub sp_receiver: Receiver,
    pub birthday: u32,
    pub last_scan: u32,
    #[serde_as(as = "HashMap<DisplayFromStr, _>")]
    owned: HashMap<OutPoint, OwnedOutput>,
    writer: FileWriter,
}

impl SpClient {
    pub fn new(
        label: String,
        scan_sk: SecretKey,
        spend_key: SpendKey,
        birthday: u32,
        is_testnet: bool,
        path: String,
    ) -> Result<Self> {
        let secp = Secp256k1::signing_only();
        let scan_pubkey = scan_sk.public_key(&secp);
        let sp_receiver: Receiver;
        match spend_key {
            SpendKey::Public(key) => {
                sp_receiver = Receiver::new(0, scan_pubkey, key, is_testnet)?;
            },
            SpendKey::Secret(key) => {
                let spend_pubkey = key.public_key(&secp);
                sp_receiver = Receiver::new(0, scan_pubkey, spend_pubkey, is_testnet)?;
            }
        }
        let writer = FileWriter::new(path, label.clone())?;

        Ok(Self {
            label,
            scan_sk,
            spend_key,
            sp_receiver,
            birthday,
            last_scan: if birthday == 0 {0} else {birthday - 1},
            owned: HashMap::new(),
            writer
        })
    }

    pub fn try_init_from_disk(label: String, path: String) -> Result<SpClient> {
        let empty = SpClient::new(
            label,
            SecretKey::from_slice(&[1u8; SECRET_KEY_SIZE]).unwrap(),
            SpendKey::Secret(SecretKey::from_slice(&[1u8; SECRET_KEY_SIZE]).unwrap()),
            0,
            false,
            path,
        )?;

        empty.retrieve_from_disk()
    }

    pub fn update_last_scan(&mut self, scan_height: u32) {
        self.last_scan = scan_height;
    }

    pub fn get_total_amt(&self) -> u64 {
        self.owned.values()
            .filter(|x| !x.spent)
            .fold(0, |acc, x| acc + x.amount)
    }

    pub fn extend_owned(&mut self, owned: Vec<(OutPoint, OwnedOutput)>) {
        self.owned.extend(owned.into_iter());
    }

    pub fn check_outpoint_owned(&self, outpoint: OutPoint) -> bool {
        self.owned.contains_key(&outpoint)
    }

    pub fn mark_outpoint_spent(&mut self, outpoint: OutPoint) -> Result<()> {
        let owned = self.owned.get_mut(&outpoint);
        match owned {
            Some(owned) => {
                loginfo(format!("marked {} as spent", owned.txoutpoint).as_str());
                owned.spent = true;
                Ok(())
            }
            None => Err(anyhow::anyhow!("owned outpoint not found")),
        }
    }

    pub fn list_outpoints(&self) -> Vec<OwnedOutput> {
        self.owned.values().cloned().collect()
    }

    pub fn reset_from_blockheight(self, blockheight: u32) -> Self {
        let mut new = self.clone();
        new.owned = HashMap::new();
        new.owned = self
            .owned
            .into_iter()
            .filter(|o| o.1.blockheight <= blockheight)
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

    pub fn delete_from_disk(self) -> Result<()> {
        self.writer.delete()
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
) -> Result<(Mnemonic, SecretKey, SecretKey)> {
    let mnemonic = if seedphrase.is_empty() { Mnemonic::generate(12)? } else { Mnemonic::parse(seedphrase)? };
    let seed = mnemonic.to_seed(passphrase);

    let network = if is_testnet { Network::Testnet } else { Network::Bitcoin };

    let xprv = Xpriv::new_master(network, &seed)?;

    let (scan_privkey, spend_privkey) = derive_keys_from_xprv(xprv)?;

    Ok((mnemonic, scan_privkey, spend_privkey))
}

fn derive_keys_from_xprv(xprv: Xpriv) -> Result<(SecretKey, SecretKey)> {
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
