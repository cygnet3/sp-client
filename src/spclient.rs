use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use bip39::{
    rand::{self, seq::SliceRandom},
    Mnemonic,
};

use bitcoin::psbt::{raw, Input, Output};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    consensus::{deserialize, serialize},
    hashes::hex::FromHex,
    key::TapTweak,
    psbt::PsbtSighashType,
    secp256k1::{
        constants::SECRET_KEY_SIZE, Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey,
        ThirtyTwoByteHash,
    },
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    Address, Amount, Network, ScriptBuf, TapLeafHash, Transaction, TxIn, TxOut, Witness,
};
use log::info;
use nakamoto::common::bitcoin::OutPoint;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DisplayFromStr;

use silentpayments::{receiving::Receiver, utils::LabelHash};
use silentpayments::sending::SilentPaymentAddress;
use silentpayments::utils as sp_utils;

use anyhow::{Error, Result};

use crate::constants::{
    NUMS, PSBT_SP_ADDRESS_KEY, PSBT_SP_PREFIX, PSBT_SP_SUBTYPE, PSBT_SP_TWEAK_KEY,
};
use crate::db::FileWriter;

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
        let change_label = LabelHash::from_b_scan_and_m(scan_sk, 0).to_scalar();
        match spend_key {
            SpendKey::Public(key) => {
                sp_receiver = Receiver::new(0, scan_pubkey, key, change_label.into(), is_testnet)?;
            },
            SpendKey::Secret(key) => {
                let spend_pubkey = key.public_key(&secp);
                sp_receiver = Receiver::new(0, scan_pubkey, spend_pubkey, change_label.into(), is_testnet)?;
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
                info!("marked {} as spent", owned.txoutpoint);
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

    pub fn fill_sp_outputs(&self, psbt: &mut Psbt) -> Result<()> {
        let b_spend = match self.spend_key {
            SpendKey::Secret(key) => key,
            SpendKey::Public(_) => return Err(Error::msg("Watch-only wallet, can't spend"))
        };

        let mut input_privkeys: Vec<SecretKey> = vec![];
        for (i, input) in psbt.inputs.iter().enumerate() {
            if let Some(tweak) = input.proprietary.get(&raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_TWEAK_KEY.as_bytes().to_vec()
            }) {
                let mut buffer = [0u8;32];
                if tweak.len() != 32 {return Err(Error::msg(format!("Invalid tweak at input {}", i)))}
                buffer.copy_from_slice(tweak.as_slice());
                let scalar = Scalar::from_be_bytes(buffer)?;
                input_privkeys.push(b_spend.add_tweak(&scalar)?);
            } else {
                // For now all inputs belong to us
                return Err(Error::msg(format!("Missing tweak at input {}", i)));
            }
        }

        let a_sum = Self::get_a_sum_secret_keys(&input_privkeys);
        let outpoints: Vec<(String, u32)> = psbt.unsigned_tx.input.iter()
            .map(|i| {
                let prev_out = i.previous_output;
                (prev_out.txid.to_string(), prev_out.vout)
            })
            .collect();
        let outpoints_hash: Scalar = sp_utils::hash_outpoints(&outpoints, a_sum.public_key(&Secp256k1::signing_only()))?;
        let partial_secret = sp_utils::sending::sender_calculate_partial_secret(a_sum, outpoints_hash)?;
        for (i, output) in psbt.unsigned_tx.output.iter_mut().enumerate() {
            // get the sp address from psbt
            let output_data = &psbt.outputs[i];
            if let Some(value) = output_data.proprietary.get(&raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec()
            }) {
                // Create the right output key
                let sp_address = SilentPaymentAddress::try_from(deserialize::<String>(&value)?)?;
                let output_key = silentpayments::sending::generate_recipient_pubkey(sp_address.into(), partial_secret)?;
                // update the script pubkey
                output.script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key.dangerous_assume_tweaked());
            } else {
                // Not a sp output
                continue;
            }
        };
        Ok(())
    }

    pub fn set_fees(psbt: &mut Psbt, fee_rate: u32, payer: String) -> Result<()> {
        let payer_vouts: Vec<u32> = match SilentPaymentAddress::try_from(payer.clone()) {
            Ok(sp_address) => {
                psbt.outputs.iter().enumerate()
                    .filter_map(|(i, o)| {
                        if let Some(value) = o.proprietary.get(&raw::ProprietaryKey {
                            prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                            subtype: PSBT_SP_SUBTYPE,
                            key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec()
                        }) {
                            let candidate = SilentPaymentAddress::try_from(deserialize::<String>(&value).unwrap()).unwrap();
                            if sp_address == candidate {Some(i as u32)} else {None}
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            Err(_) => {
                let address = Address::from_str(&payer)?;
                let spk = address.assume_checked().script_pubkey();
                psbt.unsigned_tx.output.iter().enumerate()
                    .filter_map(|(i, o)| {
                        if o.script_pubkey == spk { Some(i as u32)} else {None}
                    })
                    .collect() // Actually we should have only one output for normal address
            },
        };

        if payer_vouts.is_empty() {return Err(Error::msg("Payer is not part of this transaction"))}

        // check against the total amt in inputs
        let total_input_amt: u64 = psbt.iter_funding_utxos().try_fold(0u64, |sum, utxo_result| {
            utxo_result.map(|utxo| sum + utxo.value.to_sat())
        })?;

        // total amt in outputs should be equal
        let total_output_amt: u64 = psbt.unsigned_tx.output.iter().fold(0, |sum, add| sum + add.value.to_sat());
        
        if total_input_amt != total_output_amt {
            return Err(Error::msg("Total inputs/outputs amount is not the same"));
        }

        // now compute the size of the tx
        let fake = Self::sign_psbt_fake(psbt);
        let vsize = fake.vsize();

        // absolut amount of fees
        let fee_amt: u64 = (fee_rate * vsize as u32).into();

        // now deduce the fees from one of the payer outputs
        let mut rng = bip39::rand::thread_rng();
        if let Some(deduce_from) = payer_vouts.choose(&mut rng) {
            let output = &mut psbt.unsigned_tx.output[*deduce_from as usize];
            let old_value = output.value;
            output.value = old_value - Amount::from_sat(fee_amt);
        } else {return Err(Error::msg("no payer vout"))}

        Ok(())
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

    pub fn get_a_sum_secret_keys(input: &Vec<SecretKey>) -> SecretKey {
        let secp = Secp256k1::new();

        let mut negated_keys: Vec<SecretKey> = vec![];

        for key in input {
            let (_, parity) = key.x_only_public_key(&secp);

            if parity == bitcoin::secp256k1::Parity::Odd {
                negated_keys.push(key.negate());
            } else {
                negated_keys.push(key.clone());
            }
        }

        let (head, tail) = negated_keys.split_first().unwrap();

        let result: SecretKey = tail
            .iter()
            .fold(*head, |acc, &item| acc.add_tweak(&item.into()).unwrap());

        result
    }

    fn taproot_sighash<T: std::ops::Deref<Target = Transaction> + std::borrow::Borrow<Transaction>> (
            input: &Input,
            prevouts: &Vec<&TxOut>,
            input_index: usize,
            cache: &mut SighashCache<T>,
            tapleaf_hash: Option<TapLeafHash>
        ) -> Result<(Message, PsbtSighashType), Error> {
        let prevouts = Prevouts::All(prevouts);

        let hash_ty = input
            .sighash_type
            .map(|ty| ty.taproot_hash_ty())
            .unwrap_or(Ok(bitcoin::TapSighashType::Default))?;

        let sighash = match tapleaf_hash {
            Some(leaf_hash) => cache.taproot_script_spend_signature_hash(
                input_index,
                &prevouts,
                leaf_hash,
                hash_ty,
            )?,
            None => cache.taproot_key_spend_signature_hash(input_index, &prevouts, hash_ty)?,
        };
        let msg = Message::from_digest(sighash.into_32());
        Ok((msg, hash_ty.into()))
    }

    // Sign a transaction with garbage, used for easier fee estimation
    fn sign_psbt_fake(psbt: &Psbt) -> Transaction {
        let mut fake_psbt = psbt.clone();

        let fake_sig = [1u8;64];

        for i in fake_psbt.inputs.iter_mut() {
            i.tap_key_sig = Some(Signature::from_slice(&fake_sig).unwrap());
        }

        Self::finalize_psbt(&mut fake_psbt).unwrap();
        let tx = fake_psbt.extract_tx().expect("Invalid fake tx");
        tx
    }

    pub fn sign_psbt(
            &self,
            psbt: Psbt,
        ) -> Result<Psbt> {
        let b_spend = match self.spend_key {
            SpendKey::Secret(key) => key,
            SpendKey::Public(_) => return Err(Error::msg("Watch-only wallet, can't spend"))
        };

        let mut cache = SighashCache::new(&psbt.unsigned_tx);

        let mut prevouts: Vec<&TxOut> = vec![];

        for input in &psbt.inputs {
            if let Some(witness_utxo) = &input.witness_utxo {
                prevouts.push(witness_utxo);
            }
        }

        let mut signed_psbt = psbt.clone();

        let secp = Secp256k1::signing_only();

        for (i, input) in psbt.inputs.iter().enumerate() {
            
            let tap_leaf_hash: Option<TapLeafHash> = None;

            let (msg, sighash_ty) = Self::taproot_sighash(&input, &prevouts, i, &mut cache, tap_leaf_hash)?;

            // Construct the signing key
            let tweak = input.proprietary.get(&raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_TWEAK_KEY.as_bytes().to_vec()
            });

            if tweak.is_none() { panic!("Missing tweak") };

            let tweak = SecretKey::from_slice(tweak.unwrap().as_slice()).unwrap();

            let sk = b_spend.add_tweak(&tweak.into())?;

            let keypair = Keypair::from_secret_key(&secp, &sk);

            let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut rand::thread_rng());

            signed_psbt.inputs[i].tap_key_sig = Some(Signature { sig, hash_ty: sighash_ty.taproot_hash_ty()? });
        }

        Ok(signed_psbt)
    }

    pub(crate) fn finalize_psbt(psbt: &mut Psbt) -> Result<()> {
        psbt.inputs.iter_mut()
            .for_each(|i| {
                let mut script_witness = Witness::new();
                if let Some(sig) = i.tap_key_sig {
                    script_witness.push(sig.to_vec());
                } else {
                    panic!("Missing signature");
                }

                i.final_script_witness = Some(script_witness);

                // Clear all the data fields as per the spec.
                i.tap_key_sig = None;
                i.partial_sigs = BTreeMap::new();
                i.sighash_type = None;
                i.redeem_script = None;
                i.witness_script = None;
                i.bip32_derivation = BTreeMap::new();
            });
        Ok(())
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
