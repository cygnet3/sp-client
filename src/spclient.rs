use std::{collections::{BTreeMap, HashMap}, str::FromStr};

use bip39::{rand::{self, seq::SliceRandom}, Mnemonic};

use bitcoin::{
    bip32::{DerivationPath, Xpriv}, consensus::{deserialize, serialize}, hashes::hex::FromHex, key::TapTweak, psbt::PsbtSighashType, secp256k1::{constants::SECRET_KEY_SIZE, Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, ThirtyTwoByteHash}, sighash::{Prevouts, SighashCache}, taproot::Signature, Address, Amount, Network, ScriptBuf, TapLeafHash, Transaction, TxIn, TxOut, Witness
};
use bitcoin::psbt::{Input, Output, raw};
use nakamoto::common::bitcoin::OutPoint;

use serde::{Serialize, Deserialize};
use serde_with::serde_as;
use serde_with::DisplayFromStr;

use silentpayments::receiving::Receiver;
use silentpayments::sending::SilentPaymentAddress;
use silentpayments::utils as sp_utils;

use anyhow::{Result, Error};

use crate::{db::FileWriter, stream::loginfo};
use crate::constants::{PSBT_SP_ADDRESS_KEY, PSBT_SP_PREFIX, PSBT_SP_SUBTYPE, PSBT_SP_TWEAK_KEY, NUMS};

pub use bitcoin::psbt::Psbt;

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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Recipient {
    pub address: String, // either old school or silent payment
    pub amount: u64,
    pub nb_outputs: u32 // if address is not SP, only 1 is valid
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

    pub fn create_new_psbt(inputs: Vec<OwnedOutput>, recipients: Vec<Recipient>) -> Result<Psbt> {
        let mut network: Option<Network> = None;
        let mut tx_in: Vec<bitcoin::TxIn> = vec![];
        let mut inputs_data: Vec<(ScriptBuf, u64, Scalar)> = vec![];

        for i in inputs {
            tx_in.push(TxIn { 
                previous_output: bitcoin::OutPoint::from_str(&i.txoutpoint)?,
                script_sig: ScriptBuf::new(), 
                sequence: bitcoin::Sequence::MAX, 
                witness: bitcoin::Witness::new()
            });

            let scalar = Scalar::from_be_bytes(FromHex::from_hex(&i.tweak)?)?;

            inputs_data.push((ScriptBuf::from_hex(&i.script)?, i.amount, scalar));
        }

        // Since we don't have access to private materials for now we use a NUMS key as a placeholder 
        let placeholder_key = bitcoin::XOnlyPublicKey::from_str(NUMS)?.dangerous_assume_tweaked();

        let _outputs: Result<Vec<bitcoin::TxOut>> = recipients.iter()
            .map(|o| {
                let address: Address;

                match SilentPaymentAddress::try_from(o.address.as_str()) {
                    Ok(sp_address) => {
                        let address_network = if sp_address.is_testnet() { Network::Testnet } else { Network::Bitcoin };

                        if let Some(network) = network {
                            if network != address_network { return Err(Error::msg(format!("Wrong network for address {}", sp_address)))}
                        } else {
                            network = Some(address_network);
                        }

                        address = Address::from_script(&ScriptBuf::new_p2tr_tweaked(placeholder_key), address_network).unwrap();
                    },
                    Err(_) => {
                        let unchecked_address = Address::from_str(&o.address)?; // TODO: handle better garbage string

                        if let Some(network) = network {
                            if network != *unchecked_address.network() { return Err(Error::msg(format!("Wrong network for address {}", unchecked_address.assume_checked())))}
                        } else {
                            network = Some(*unchecked_address.network());
                        }

                        address = unchecked_address.assume_checked();
                    },
                }

                Ok(TxOut {
                    value: Amount::from_sat(o.amount),
                    script_pubkey: address.script_pubkey()
                })
            })
            .collect();

        let outputs = _outputs?;

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: tx_in,
            output: outputs
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        // Add the witness utxo to the input in psbt
        for (i, input_data) in inputs_data.iter().enumerate() {
            let (script_pubkey, value, tweak) = input_data;
            let witness_txout = TxOut {
                value: Amount::from_sat(*value),
                script_pubkey: script_pubkey.clone()
            };
            let mut psbt_input = Input { witness_utxo: Some(witness_txout), ..Default::default() };
            psbt_input.proprietary.insert(raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_TWEAK_KEY.as_bytes().to_vec()
            }, tweak.to_be_bytes().to_vec());
            psbt.inputs[i] = psbt_input;
        }
        
        for (i, recipient) in recipients.iter().enumerate() {
            if let Ok(sp_address) = SilentPaymentAddress::try_from(recipient.address.as_str()) {
                // Add silentpayment address to the output
                let mut psbt_output = Output { ..Default::default() };
                psbt_output.proprietary.insert(raw::ProprietaryKey {
                    prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                    subtype: PSBT_SP_SUBTYPE,
                    key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec()
                }, serialize(&sp_address.to_string()));
                psbt.outputs[i] = psbt_output;
            } else {
                // Regular address, we don't need to add more data
                continue;
            }
        }

        Ok(psbt)
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
