use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    str::FromStr,
};

use bitcoin::{
    absolute::Height,
    bip32::{DerivationPath, Xpriv},
    consensus::{deserialize, serialize},
    hex::DisplayHex,
    key::{constants::ONE, TapTweak},
    psbt::PsbtSighashType,
    script::PushBytesBuf,
    secp256k1::{Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, ThirtyTwoByteHash},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, TapLeafHash, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use bitcoin::{
    hashes::Hash,
    psbt::{raw, Input, Output},
};
use serde::{Deserialize, Serialize};

use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils as sp_utils;
use silentpayments::utils::{Network as SpNetwork, SilentPaymentAddress};

use anyhow::{Error, Result};

use crate::constants::{
    DATA_CARRIER_SIZE, DUST_THRESHOLD, NUMS, PSBT_SP_ADDRESS_KEY, PSBT_SP_PREFIX, PSBT_SP_SUBTYPE,
    PSBT_SP_TWEAK_KEY,
};

pub use bitcoin::psbt::Psbt;

type SpendingTxId = String;
type MinedInBlock = String;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum RecordedTransaction {
    Incoming(RecordedTransactionIncoming),
    Outgoing(RecordedTransactionOutgoing),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RecordedTransactionIncoming {
    pub txid: Txid,
    pub amount: Amount,
    pub confirmed_at: Option<Height>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RecordedTransactionOutgoing {
    pub txid: Txid,
    pub spent_outpoints: Vec<OutPoint>,
    pub recipients: Vec<Recipient>,
    pub confirmed_at: Option<Height>,
    pub change: Amount,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum OutputSpendStatus {
    Unspent,
    Spent(SpendingTxId),
    Mined(MinedInBlock),
}

type WalletFingerprint = [u8; 8];

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OwnedOutput {
    pub blockheight: u32,
    pub tweak: String,
    pub amount: Amount,
    pub script: String,
    pub label: Option<String>,
    pub spend_status: OutputSpendStatus,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct OutputList {
    pub wallet_fingerprint: WalletFingerprint,
    birthday: u32,
    last_scan: u32,
    outputs: HashMap<OutPoint, OwnedOutput>,
}

impl OutputList {
    pub fn new(scan_pk: PublicKey, spend_pk: PublicKey, birthday: u32) -> Self {
        // take a fingerprint of the wallet by hashing its keys
        let mut engine = silentpayments::bitcoin_hashes::sha256::HashEngine::default();
        engine
            .write_all(&scan_pk.serialize())
            .expect("Failed to write scan_pk to engine");
        engine
            .write_all(&spend_pk.serialize())
            .expect("Failed to write spend_pk to engine");
        let hash = silentpayments::bitcoin_hashes::sha256::Hash::from_engine(engine);
        let mut wallet_fingerprint = [0u8; 8];
        wallet_fingerprint.copy_from_slice(&hash.to_byte_array()[..8]);
        let outputs = HashMap::new();
        Self {
            wallet_fingerprint,
            outputs,
            birthday,
            last_scan: birthday,
        }
    }

    pub fn check_fingerprint(&self, client: &SpClient) -> bool {
        let sp_address: SilentPaymentAddress = client.get_receiving_address().try_into().unwrap();
        let new = Self::new(sp_address.get_scan_key(), sp_address.get_spend_key(), 0);
        new.wallet_fingerprint == self.wallet_fingerprint
    }

    pub fn get_birthday(&self) -> u32 {
        self.birthday
    }

    pub fn get_last_scan(&self) -> u32 {
        self.last_scan
    }

    pub fn set_birthday(&mut self, new_birthday: u32) {
        self.birthday = new_birthday;
    }

    pub fn update_last_scan(&mut self, scan_height: u32) {
        self.last_scan = scan_height;
    }

    fn reset_to_height(&mut self, height: u32) {
        let new_outputs = self
            .to_outpoints_list()
            .into_iter()
            .filter(|(_, o)| o.blockheight < height)
            .collect::<HashMap<OutPoint, OwnedOutput>>();
        self.outputs = new_outputs;
    }

    pub fn to_outpoints_list(&self) -> HashMap<OutPoint, OwnedOutput> {
        self.outputs.clone()
    }

    pub fn extend_from(&mut self, new: HashMap<OutPoint, OwnedOutput>) {
        self.outputs.extend(new);
    }

    pub fn get_balance(&self) -> Amount {
        self.outputs
            .iter()
            .filter(|(_, o)| o.spend_status == OutputSpendStatus::Unspent)
            .fold(Amount::from_sat(0), |acc, x| acc + x.1.amount)
    }

    pub fn to_spendable_list(&self) -> HashMap<OutPoint, OwnedOutput> {
        self.to_outpoints_list()
            .into_iter()
            .filter(|(_, o)| o.spend_status == OutputSpendStatus::Unspent)
            .collect()
    }

    pub fn get_outpoint(&self, outpoint: OutPoint) -> Result<(OutPoint, OwnedOutput)> {
        let output = self
            .to_outpoints_list()
            .get_key_value(&outpoint)
            .ok_or_else(|| Error::msg("Outpoint not in list"))?
            .1
            .to_owned();

        Ok((outpoint, output))
    }

    pub fn mark_spent(
        &mut self,
        outpoint: OutPoint,
        spending_tx: Txid,
        force_update: bool,
    ) -> Result<()> {
        let (outpoint, mut output) = self.get_outpoint(outpoint)?;

        match output.spend_status {
            OutputSpendStatus::Unspent => {
                let tx_hex = spending_tx.to_string();
                output.spend_status = OutputSpendStatus::Spent(tx_hex);
                self.outputs.insert(outpoint, output);
                Ok(())
            }
            OutputSpendStatus::Spent(tx_hex) => {
                // We may want to fail if that's the case, or force update if we know what we're doing
                if force_update {
                    let tx_hex = spending_tx.to_string();
                    output.spend_status = OutputSpendStatus::Spent(tx_hex);
                    self.outputs.insert(outpoint, output);
                    Ok(())
                } else {
                    Err(Error::msg(format!(
                        "Output already spent by transaction {}",
                        tx_hex
                    )))
                }
            }
            OutputSpendStatus::Mined(block) => Err(Error::msg(format!(
                "Output already mined in block {}",
                block
            ))),
        }
    }

    /// Mark the output as being spent in block `mined_in_block`
    /// We don't really need to check the previous status, if it's in a block there's nothing we can do
    pub fn mark_mined(&mut self, outpoint: OutPoint, mined_in_block: BlockHash) -> Result<()> {
        let (outpoint, mut output) = self.get_outpoint(outpoint)?;

        let block_hex = mined_in_block.to_string();
        output.spend_status = OutputSpendStatus::Mined(block_hex);
        self.outputs.insert(outpoint, output);
        Ok(())
    }

    /// Revert the outpoint status to Unspent, regardless of the current status
    /// This could be useful on some rare occurrences, like a transaction falling out of mempool after a while
    /// Watch out we also reverse the mined state, use with caution
    pub fn revert_spent_status(&mut self, outpoint: OutPoint) -> Result<()> {
        let (outpoint, mut output) = self.get_outpoint(outpoint)?;

        if output.spend_status != OutputSpendStatus::Unspent {
            output.spend_status = OutputSpendStatus::Unspent;
            self.outputs.insert(outpoint, output);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Recipient {
    pub address: String, // either old school or silent payment
    pub amount: Amount,
    pub nb_outputs: u32, // if address is not SP, only 1 is valid
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum SpendKey {
    Secret(SecretKey),
    Public(PublicKey),
}

impl TryInto<SecretKey> for SpendKey {
    type Error = anyhow::Error;
    fn try_into(self) -> std::prelude::v1::Result<SecretKey, Error> {
        match self {
            Self::Secret(k) => Ok(k),
            Self::Public(_) => Err(Error::msg("Can't take SecretKey from Public")),
        }
    }
}

impl Into<PublicKey> for SpendKey {
    fn into(self) -> PublicKey {
        match self {
            Self::Secret(k) => {
                let secp = Secp256k1::signing_only();
                k.public_key(&secp)
            }
            Self::Public(p) => p,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SpClient {
    pub label: String,
    scan_sk: SecretKey,
    spend_key: SpendKey,
    mnemonic: Option<String>,
    pub sp_receiver: Receiver,
    network: Network,
}

impl Default for SpClient {
    fn default() -> Self {
        let default_sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let default_pubkey = XOnlyPublicKey::from_str(NUMS)
            .unwrap()
            .public_key(bitcoin::key::Parity::Even);
        Self {
            label: "default".to_owned(),
            scan_sk: default_sk,
            spend_key: SpendKey::Secret(default_sk),
            mnemonic: None,
            sp_receiver: Receiver::new(
                0,
                default_pubkey,
                default_pubkey,
                Scalar::from_be_bytes(ONE).unwrap().into(),
                SpNetwork::Regtest,
            )
            .unwrap(),
            network: Network::Regtest,
        }
    }
}

impl SpClient {
    pub fn new(
        label: String,
        scan_sk: SecretKey,
        spend_key: SpendKey,
        mnemonic: Option<String>,
        network: Network,
    ) -> Result<Self> {
        let secp = Secp256k1::signing_only();
        let scan_pubkey = scan_sk.public_key(&secp);
        let sp_receiver: Receiver;
        let change_label = Label::new(scan_sk, 0);

        let sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Regtest => SpNetwork::Regtest,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            _ => unreachable!(),
        };
        match spend_key {
            SpendKey::Public(key) => {
                sp_receiver = Receiver::new(0, scan_pubkey, key, change_label.into(), sp_network)?;
            }
            SpendKey::Secret(key) => {
                let spend_pubkey = key.public_key(&secp);
                sp_receiver = Receiver::new(
                    0,
                    scan_pubkey,
                    spend_pubkey,
                    change_label.into(),
                    sp_network,
                )?;
            }
        }

        Ok(Self {
            label,
            scan_sk,
            spend_key,
            mnemonic,
            sp_receiver,
            network,
        })
    }

    pub fn get_receiving_address(&self) -> String {
        self.sp_receiver.get_receiving_address()
    }

    pub fn get_scan_key(&self) -> SecretKey {
        self.scan_sk
    }

    pub fn get_spend_key(&self) -> SpendKey {
        self.spend_key.clone()
    }

    pub fn get_mnemonic(&self) -> Option<String> {
        self.mnemonic.clone()
    }

    pub fn get_network(&self) -> Network {
        self.network
    }

    pub fn try_get_secret_spend_key(&self) -> Result<SecretKey> {
        match self.spend_key {
            SpendKey::Public(_) => Err(Error::msg("Don't have secret key")),
            SpendKey::Secret(sk) => Ok(sk),
        }
    }

    pub fn get_partial_secret_from_psbt(&self, psbt: &Psbt) -> Result<SecretKey> {
        let b_spend = match self.spend_key {
            SpendKey::Secret(key) => key,
            SpendKey::Public(_) => return Err(Error::msg("Watch-only wallet, can't spend")),
        };

        // TODO: create a struct for `InputPrivKeys` or smth like that
        let mut input_privkeys: Vec<(SecretKey, bool)> = vec![];
        for (i, input) in psbt.inputs.iter().enumerate() {
            if let Some(tweak) = input.proprietary.get(&raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_TWEAK_KEY.as_bytes().to_vec(),
            }) {
                let sk = SecretKey::from_slice(&tweak)?;
                let input_key = b_spend.add_tweak(&sk.into())?;
                // we add `true` for every key since we only handle silent payments outputs as input
                input_privkeys.push((input_key, true));
                // TODO: add the derivation logic to be able to use non sp output as inputs
                // TODO: add a psbt field to hold the tweak when some outputs are not ours
            } else {
                // For now we own all inputs and they're all silent payments outputs
                return Err(Error::msg(format!("Missing tweak at input {}", i)));
            }
        }

        let outpoints: Vec<(String, u32)> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|i| {
                let prev_out = i.previous_output;
                (prev_out.txid.to_string(), prev_out.vout)
            })
            .collect();

        let partial_secret =
            sp_utils::sending::calculate_partial_secret(&input_privkeys, &outpoints)?;

        Ok(partial_secret)
    }

    pub fn replace_op_return_with(psbt: &mut Psbt, new_data: &[u8]) -> Result<()> {
        psbt.unsigned_tx
            .output
            .iter_mut()
            .filter(|o| o.script_pubkey.is_op_return())
            .for_each(|o| {
                let mut op_return = PushBytesBuf::new();
                op_return.extend_from_slice(new_data).unwrap();
                o.script_pubkey = ScriptBuf::new_op_return(op_return);
            });
        Ok(())
    }

    pub fn fill_sp_outputs(&self, psbt: &mut Psbt, partial_secret: SecretKey) -> Result<()> {
        // get all the silent addresses
        let mut sp_addresses: Vec<String> = Vec::with_capacity(psbt.outputs.len());
        for output in psbt.outputs.iter() {
            // get the sp address from psbt
            if let Some(value) = output.proprietary.get(&raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec(),
            }) {
                let sp_address = SilentPaymentAddress::try_from(deserialize::<String>(value)?)?;
                sp_addresses.push(sp_address.into());
            } else {
                // Not a sp output
                continue;
            }
        }

        let mut sp_address2xonlypubkeys =
            silentpayments::sending::generate_recipient_pubkeys(sp_addresses, partial_secret)?;
        // We iterate twice over outputs, it would make sense to have some kind of stateful struct to keep tracks of key generated and do everything in one go
        for (i, output) in psbt.unsigned_tx.output.iter_mut().enumerate() {
            // get the sp address from psbt
            let output_data = &psbt.outputs[i];
            if let Some(value) = output_data.proprietary.get(&raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec(),
            }) {
                let sp_address = SilentPaymentAddress::try_from(deserialize::<String>(value)?)?;
                if let Some(xonlypubkeys) = sp_address2xonlypubkeys.get_mut(&sp_address.to_string())
                {
                    if !xonlypubkeys.is_empty() {
                        let output_key = xonlypubkeys.remove(0);
                        // update the script pubkey
                        output.script_pubkey =
                            ScriptBuf::new_p2tr_tweaked(output_key.dangerous_assume_tweaked());
                    } else {
                        return Err(Error::msg(format!(
                            "We're missing a key for address {}",
                            sp_address
                        )));
                    }
                } else {
                    return Err(Error::msg(format!("Can't find address {}", sp_address)));
                }
            } else {
                // Not a sp output
                continue;
            }
        }
        for (_, xonlypubkeys) in sp_address2xonlypubkeys {
            debug_assert!(xonlypubkeys.is_empty());
        }
        Ok(())
    }

    pub fn set_fees(psbt: &mut Psbt, fee_rate: Amount, payer: String) -> Result<()> {
        // just take the first output that belong to payer
        // it would be interesting to randomize the outputs we pick,
        // or scatter the fee amount on all the outputs of the payer
        // or maybe divide the fee amongst all the participants of the transaction
        let payer_vout = match SilentPaymentAddress::try_from(payer.clone()) {
            Ok(sp_address) => psbt
                .outputs
                .iter()
                .enumerate()
                .find(|(_, o)| {
                    if let Some(value) = o.proprietary.get(&raw::ProprietaryKey {
                        prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                        subtype: PSBT_SP_SUBTYPE,
                        key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec(),
                    }) {
                        let candidate =
                            SilentPaymentAddress::try_from(deserialize::<String>(value).unwrap())
                                .unwrap();
                        sp_address == candidate
                    } else {
                        false
                    }
                })
                .map(|(i, _)| i),
            Err(_) => {
                let address = Address::from_str(&payer)?;
                let spk = address.assume_checked().script_pubkey();
                psbt.unsigned_tx
                    .output
                    .iter()
                    .enumerate()
                    .find(|(_, o)| o.script_pubkey == spk)
                    .map(|(i, _)| i)
            }
        };

        if payer_vout.is_none() {
            return Err(Error::msg("Payer is not part of this transaction"));
        }

        // check against the total amt in inputs
        let total_input_amt: Amount = psbt
            .iter_funding_utxos()
            .try_fold(Amount::from_sat(0), |sum, utxo_result| {
                utxo_result.map(|utxo| sum + utxo.value)
            })?;

        let total_output_amt: Amount = psbt
            .unsigned_tx
            .output
            .iter()
            .fold(Amount::from_sat(0), |sum, add| sum + add.value);

        let dust = total_input_amt
            .checked_sub(total_output_amt)
            .ok_or(Error::msg("Not enough funds"))?;

        if dust > DUST_THRESHOLD {
            return Err(Error::msg("Missing a change output"));
        }

        // now compute the size of the tx
        let fake = Self::sign_psbt_fake(psbt);
        let vsize = fake.weight().to_vbytes_ceil();

        // absolut amount of fees
        let fee_amt = fee_rate
            .checked_mul(vsize)
            .ok_or_else(|| Error::msg("Fee rate multiplication overflowed"))?;

        // now deduce the fees from one of the payer outputs
        // TODO deduce fee from the change address
        if fee_amt > dust {
            let output = &mut psbt.unsigned_tx.output[payer_vout.unwrap()];
            let old_value = output.value;
            output.value = old_value
                .checked_sub(fee_amt - dust)
                .ok_or(Error::msg("Not enough funds"))?; // account for eventual dust
        }

        Ok(())
    }

    pub fn create_new_psbt(
        &self,
        utxos: HashMap<OutPoint, OwnedOutput>,
        mut recipients: Vec<Recipient>,
        payload: Option<&[u8]>,
    ) -> Result<(Psbt, Option<usize>)> {
        let mut change_idx = None;
        let mut tx_in: Vec<bitcoin::TxIn> = vec![];
        let mut inputs_data: Vec<(ScriptBuf, Amount, Scalar)> = vec![];
        let mut total_input_amount = Amount::from_sat(0);
        let mut total_output_amount = Amount::from_sat(0);

        for (outpoint, utxo) in utxos {
            tx_in.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            });

            let scalar: Scalar = SecretKey::from_str(&utxo.tweak)?.into();

            total_input_amount = total_input_amount
                .checked_add(utxo.amount)
                .ok_or(Error::msg("Overflow on input amount"))?;

            inputs_data.push((ScriptBuf::from_hex(&utxo.script)?, utxo.amount, scalar));
        }

        // We could compute the outputs key right away,
        // but keeping things separated may be interesting,
        // for example creating transactions in a watch-only wallet
        // and using another signer
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)?.dangerous_assume_tweaked(),
        );

        let _outputs: Result<Vec<TxOut>> = recipients
            .iter()
            .map(|o| {
                let script_pubkey: ScriptBuf;

                match SilentPaymentAddress::try_from(o.address.as_str()) {
                    Ok(sp_address) => {
                        if sp_address.get_network() != self.sp_receiver.network {
                            return Err(Error::msg(format!(
                                "Wrong network for address {}",
                                sp_address
                            )));
                        }

                        script_pubkey = placeholder_spk.clone();
                    }
                    Err(_) => {
                        let unchecked_address = Address::from_str(&o.address)?; // TODO: handle better garbage string

                        let address_sp_network = match *unchecked_address.network() {
                            Network::Bitcoin => SpNetwork::Mainnet,
                            Network::Testnet | Network::Signet => SpNetwork::Testnet,
                            Network::Regtest => SpNetwork::Regtest,
                            _ => unreachable!(),
                        };

                        if self.sp_receiver.network != address_sp_network {
                            return Err(Error::msg(format!(
                                "Wrong network for address {}",
                                unchecked_address.assume_checked()
                            )));
                        }

                        script_pubkey = ScriptBuf::from_bytes(
                            unchecked_address
                                .assume_checked()
                                .script_pubkey()
                                .to_bytes(),
                        );
                    }
                }

                total_output_amount = total_output_amount
                    .checked_add(o.amount)
                    .ok_or(Error::msg("Overflow on output amount"))?;

                Ok(TxOut {
                    value: o.amount,
                    script_pubkey,
                })
            })
            .collect();

        let mut outputs = _outputs?;

        let change_amt = total_input_amount
            .checked_sub(total_output_amount)
            .ok_or(Error::msg("Not enough funds in inputs"))?;

        if change_amt > DUST_THRESHOLD {
            // Add change output
            let change_address = self.sp_receiver.get_change_address();

            change_idx = Some(outputs.len());

            outputs.push(TxOut {
                value: change_amt,
                script_pubkey: placeholder_spk,
            });

            recipients.push(Recipient {
                address: change_address,
                amount: change_amt,
                nb_outputs: 1,
            });
        }

        if let Some(data) = payload {
            if data.len() > DATA_CARRIER_SIZE {
                return Err(Error::msg(format!(
                    "Payload must be max {}B",
                    DATA_CARRIER_SIZE
                )));
            }
            let mut op_return = PushBytesBuf::new();
            op_return.extend_from_slice(data)?;
            outputs.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new_op_return(op_return),
            });
        }

        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: tx_in,
            output: outputs,
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        // Add the witness utxo to the input in psbt
        for (i, input_data) in inputs_data.iter().enumerate() {
            let (script_pubkey, value, tweak) = input_data;
            let witness_txout = TxOut {
                value: *value,
                script_pubkey: script_pubkey.clone(),
            };
            let mut psbt_input = Input {
                witness_utxo: Some(witness_txout),
                ..Default::default()
            };
            psbt_input.proprietary.insert(
                raw::ProprietaryKey {
                    prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                    subtype: PSBT_SP_SUBTYPE,
                    key: PSBT_SP_TWEAK_KEY.as_bytes().to_vec(),
                },
                tweak.to_be_bytes().to_vec(),
            );
            psbt.inputs[i] = psbt_input;
        }

        for (i, recipient) in recipients.iter().enumerate() {
            if let Ok(sp_address) = SilentPaymentAddress::try_from(recipient.address.as_str()) {
                // Add silentpayment address to the output
                let mut psbt_output = Output {
                    ..Default::default()
                };
                psbt_output.proprietary.insert(
                    raw::ProprietaryKey {
                        prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                        subtype: PSBT_SP_SUBTYPE,
                        key: PSBT_SP_ADDRESS_KEY.as_bytes().to_vec(),
                    },
                    serialize(&sp_address.to_string()),
                );
                psbt.outputs[i] = psbt_output;
            } else {
                // Regular address, we don't need to add more data
                continue;
            }
        }

        Ok((psbt, change_idx))
    }

    fn taproot_sighash<
        T: std::ops::Deref<Target = Transaction> + std::borrow::Borrow<Transaction>,
    >(
        input: &Input,
        prevouts: &Vec<&TxOut>,
        input_index: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
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

        let fake_sig = [1u8; 64];

        for i in fake_psbt.inputs.iter_mut() {
            i.tap_key_sig = Some(Signature::from_slice(&fake_sig).unwrap());
        }

        Self::finalize_psbt(&mut fake_psbt).unwrap();

        fake_psbt.extract_tx().expect("Invalid fake tx")
    }

    pub fn sign_psbt(&self, psbt: Psbt, aux_rand: &[u8; 32]) -> Result<Psbt> {
        let b_spend = match self.spend_key {
            SpendKey::Secret(key) => key,
            SpendKey::Public(_) => return Err(Error::msg("Watch-only wallet, can't spend")),
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

            let (msg, sighash_ty) =
                Self::taproot_sighash(input, &prevouts, i, &mut cache, tap_leaf_hash)?;

            // Construct the signing key
            let tweak = input.proprietary.get(&raw::ProprietaryKey {
                prefix: PSBT_SP_PREFIX.as_bytes().to_vec(),
                subtype: PSBT_SP_SUBTYPE,
                key: PSBT_SP_TWEAK_KEY.as_bytes().to_vec(),
            });

            if tweak.is_none() {
                panic!("Missing tweak")
            };

            let tweak = SecretKey::from_slice(tweak.unwrap().as_slice()).unwrap();

            let sk = b_spend.add_tweak(&tweak.into())?;

            let keypair = Keypair::from_secret_key(&secp, &sk);

            let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

            signed_psbt.inputs[i].tap_key_sig = Some(Signature {
                sig,
                hash_ty: sighash_ty.taproot_hash_ty()?,
            });
        }

        Ok(signed_psbt)
    }

    pub fn finalize_psbt(psbt: &mut Psbt) -> Result<()> {
        psbt.inputs.iter_mut().for_each(|i| {
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

    pub fn get_script_to_secret_map(
        &self,
        tweak_data_vec: Vec<PublicKey>,
    ) -> Result<HashMap<[u8; 34], PublicKey>> {
        use rayon::prelude::*;
        let b_scan = &self.get_scan_key();

        let shared_secrets: Vec<PublicKey> = tweak_data_vec
            .into_par_iter()
            .map(|tweak| sp_utils::receiving::calculate_ecdh_shared_secret(&tweak, b_scan))
            .collect();

        let items: Result<Vec<_>> = shared_secrets
            .into_par_iter()
            .map(|secret| {
                let spks = self.sp_receiver.get_spks_from_shared_secret(&secret)?;

                Ok((secret, spks.into_values()))
            })
            .collect();

        let mut res = HashMap::new();
        for (secret, spks) in items? {
            for spk in spks {
                res.insert(spk, secret);
            }
        }
        Ok(res)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SpWallet {
    client: SpClient,
    outputs: OutputList,
    tx_history: Vec<RecordedTransaction>,
}

impl SpWallet {
    pub fn new(
        client: SpClient,
        outputs: Option<OutputList>,
        tx_history: Vec<RecordedTransaction>,
    ) -> Result<Self> {
        if let Some(existing_outputs) = outputs {
            if existing_outputs.check_fingerprint(&client) {
                Ok(Self {
                    client,
                    outputs: existing_outputs,
                    tx_history,
                })
            } else {
                Err(Error::msg("outputs don't match client"))
            }
        } else {
            // Create a new outputs list
            let outputs = OutputList::new(
                client.get_scan_key().public_key(&Secp256k1::signing_only()),
                client.get_spend_key().into(),
                0,
            );
            Ok(Self {
                client,
                outputs,
                tx_history,
            })
        }
    }

    pub fn get_client(&self) -> &SpClient {
        &self.client
    }

    pub fn get_outputs(&self) -> &OutputList {
        &self.outputs
    }

    pub fn get_tx_history(&self) -> Vec<RecordedTransaction> {
        self.tx_history.clone()
    }

    pub fn get_mut_client(&mut self) -> &mut SpClient {
        &mut self.client
    }

    pub fn get_mut_outputs(&mut self) -> &mut OutputList {
        &mut self.outputs
    }

    pub fn update_wallet_with_transaction(
        &mut self,
        tx: &Transaction,
        blockheight: u32,
        partial_tweak: PublicKey,
    ) -> Result<HashMap<OutPoint, OwnedOutput>> {
        // First check that we haven't already scanned this transaction
        let txid = tx.txid();

        for i in 0..tx.output.len() {
            if self
                .get_outputs()
                .get_outpoint(OutPoint {
                    txid,
                    vout: i as u32,
                })
                .is_ok()
            {
                return Err(Error::msg("Transaction already scanned"));
            }
        }

        for input in tx.input.iter() {
            if let Ok((_, output)) = self.get_outputs().get_outpoint(input.previous_output) {
                match output.spend_status {
                    OutputSpendStatus::Spent(tx) => {
                        if tx == txid.to_string() {
                            return Err(Error::msg("Transaction already scanned"));
                        }
                    }
                    OutputSpendStatus::Mined(_) => {
                        return Err(Error::msg("Transaction already scanned"))
                    }
                    _ => continue,
                }
            }
        }

        let shared_secret = sp_utils::receiving::calculate_ecdh_shared_secret(
            &partial_tweak,
            &self.client.get_scan_key(),
        );
        let mut pubkeys_to_check: HashMap<XOnlyPublicKey, u32> = HashMap::new();
        for (vout, output) in (0u32..).zip(tx.output.iter()) {
            if output.script_pubkey.is_p2tr() {
                let xonly = XOnlyPublicKey::from_slice(&output.script_pubkey.as_bytes()[2..])?;
                pubkeys_to_check.insert(xonly, vout);
            }
        }
        let ours = self
            .client
            .sp_receiver
            .scan_transaction(&shared_secret, pubkeys_to_check.keys().cloned().collect())?;
        let mut new_outputs: HashMap<OutPoint, OwnedOutput> = HashMap::new();
        for (label, map) in ours {
            for (key, scalar) in map {
                let vout = pubkeys_to_check.get(&key).unwrap().to_owned();
                let txout = tx.output.get(vout as usize).unwrap();

                let label_str: Option<String>;
                if let Some(ref l) = label {
                    label_str = Some(l.as_string());
                } else {
                    label_str = None;
                }

                let outpoint = OutPoint::new(tx.txid(), vout);
                let owned = OwnedOutput {
                    blockheight,
                    tweak: scalar.to_be_bytes().to_lower_hex_string(),
                    amount: txout.value,
                    script: txout.script_pubkey.as_bytes().to_lower_hex_string(),
                    label: label_str,
                    spend_status: OutputSpendStatus::Unspent,
                };
                new_outputs.insert(outpoint, owned);
            }
        }
        let mut res = new_outputs.clone();
        self.outputs.extend_from(new_outputs);

        let txid = tx.txid().to_string();
        // update outputs that we own and that are spent
        for input in tx.input.iter() {
            if let Some(prevout) = self.outputs.outputs.get_mut(&input.previous_output) {
                // This is spent by this tx
                prevout.spend_status = OutputSpendStatus::Spent(txid.clone());
                res.insert(input.previous_output, prevout.clone());
            }
        }

        Ok(res)
    }

    pub fn record_outgoing_transaction(
        &mut self,
        txid: Txid,
        spent_outpoints: Vec<OutPoint>,
        recipients: Vec<Recipient>,
        change: Amount,
    ) {
        self.tx_history
            .push(RecordedTransaction::Outgoing(RecordedTransactionOutgoing {
                txid,
                spent_outpoints,
                recipients,
                confirmed_at: None,
                change,
            }))
    }

    pub fn confirm_recorded_outgoing_transaction(
        &mut self,
        outpoint: OutPoint,
        blkheight: Height,
    ) -> Result<()> {
        for recorded_tx in self.tx_history.iter_mut() {
            match recorded_tx {
                RecordedTransaction::Outgoing(outgoing)
                    if (outgoing.spent_outpoints.contains(&outpoint)) =>
                {
                    outgoing.confirmed_at = Some(blkheight);
                    return Ok(());
                }
                _ => (),
            }
        }

        Err(Error::msg(format!(
            "No outgoing tx found for input: {}",
            outpoint
        )))
    }

    pub fn record_incoming_transaction(
        &mut self,
        txid: Txid,
        amount: Amount,
        confirmed_at: Height,
    ) {
        self.tx_history
            .push(RecordedTransaction::Incoming(RecordedTransactionIncoming {
                txid,
                amount,
                confirmed_at: Some(confirmed_at),
            }))
    }

    fn reset_to_height(&mut self, blkheight: u32) {
        // reset known outputs to height
        self.outputs.reset_to_height(blkheight);

        // reset tx history to height
        self.tx_history.retain(|tx| match tx {
            RecordedTransaction::Incoming(incoming) => incoming
                .confirmed_at
                .is_some_and(|x| x.to_consensus_u32() < blkheight),
            RecordedTransaction::Outgoing(outgoing) => outgoing
                .confirmed_at
                .is_some_and(|x| x.to_consensus_u32() < blkheight),
        });
    }

    pub fn reset_to_birthday(&mut self) {
        self.reset_to_height(self.outputs.birthday);

        self.outputs.update_last_scan(self.outputs.birthday);
    }

    pub fn record_block_outputs(
        &mut self,
        height: Height,
        found_outputs: HashMap<OutPoint, OwnedOutput>,
    ) {
        // add outputs to history
        let mut txs: HashMap<Txid, Amount> = HashMap::new();
        for (outpoint, output) in found_outputs.iter() {
            let entry = txs.entry(outpoint.txid).or_default();
            *entry += output.amount;
        }
        for (txid, amount) in txs {
            self.tx_history
                .push(RecordedTransaction::Incoming(RecordedTransactionIncoming {
                    txid,
                    amount,
                    confirmed_at: Some(height),
                }))
        }

        // add outputs to known outputs
        self.outputs.extend_from(found_outputs);
    }

    pub fn record_block_inputs(
        &mut self,
        blkheight: Height,
        blkhash: BlockHash,
        found_inputs: Vec<OutPoint>,
    ) -> Result<()> {
        for outpoint in found_inputs {
            // this may confirm the same tx multiple times, but this shouldn't be a problem
            self.confirm_recorded_outgoing_transaction(outpoint, blkheight)?;
            self.outputs.mark_mined(outpoint, blkhash)?;
        }

        Ok(())
    }
}

pub fn derive_keys_from_seed(seed: &[u8; 64], network: Network) -> Result<(SecretKey, SecretKey)> {
    let xprv = Xpriv::new_master(network, seed)?;

    let (scan_privkey, spend_privkey) = derive_keys_from_xprv(xprv)?;

    Ok((scan_privkey, spend_privkey))
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
