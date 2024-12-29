use std::{
    collections::HashMap,
    io::Write,
    str::FromStr,
};

use bdk_coin_select::{
    Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, Target, TargetFee, TargetOutputs,
    TR_DUST_RELAY_MIN_VALUE, TR_KEYSPEND_TXIN_WEIGHT,
};
use bitcoin::{
    absolute::LockTime,
    key::{constants::ONE, TapTweak},
    script::PushBytesBuf,
    secp256k1::{Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, ThirtyTwoByteHash},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    transaction::Version,
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use bitcoin::hashes::Hash;
use serde::{Deserialize, Serialize};

use silentpayments::utils as sp_utils;
use silentpayments::utils::{Network as SpNetwork, SilentPaymentAddress};
use silentpayments::{
    bitcoin_hashes::sha256,
    receiving::{Label, Receiver},
};

use anyhow::{Error, Result};

use crate::constants::{
    DATA_CARRIER_SIZE, NUMS
};

use super::{
    OutputSpendStatus, OwnedOutput, Recipient, RecipientAddress, SilentPaymentUnsignedTransaction,
    SpendKey,
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SpClient {
    scan_sk: SecretKey,
    spend_key: SpendKey,
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
            scan_sk: default_sk,
            spend_key: SpendKey::Secret(default_sk),
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
    pub fn new(scan_sk: SecretKey, spend_key: SpendKey, network: Network) -> Result<Self> {
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
            scan_sk,
            spend_key,
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

    pub fn get_network(&self) -> Network {
        self.network
    }

    pub fn try_get_secret_spend_key(&self) -> Result<SecretKey> {
        match self.spend_key {
            SpendKey::Public(_) => Err(Error::msg("Don't have secret key")),
            SpendKey::Secret(sk) => Ok(sk),
        }
    }

    // For now it's only suitable for wallet that spends only silent payments outputs that it owns
    pub fn create_new_transaction(
        &self, // We need it to get the private spend key, and less importantly, the change address
        available_utxos: Vec<(String, OwnedOutput)>,
        mut recipients: Vec<Recipient>,
        fee_rate: u32,
        network: Network,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)?.dangerous_assume_tweaked(),
        );

        let address_sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            Network::Regtest => SpNetwork::Regtest,
            _ => unreachable!(),
        };

        let mut sp_addresses = vec![];
        let _outputs: Result<Vec<TxOut>> = recipients
            .iter()
            .map(|r| {
                let script_pubkey = match &r.address {
                    RecipientAddress::SpAddress(sp_address) => {
                        if sp_address.get_network() != address_sp_network {
                            return Err(Error::msg(format!(
                                "Wrong network for address {}",
                                sp_address
                            )));
                        }

                        sp_addresses.push(sp_address.clone());

                        placeholder_spk.clone()
                    }
                    RecipientAddress::LegacyAddress(unchecked_address) => ScriptBuf::from_bytes(
                        unchecked_address
                            .clone()
                            .require_network(network)?
                            .script_pubkey()
                            .to_bytes(),
                    ),
                    RecipientAddress::Data(data) => {
                        if r.amount > Amount::from_sat(0) {
                            return Err(Error::msg("Data output must have an amount of 0!"));
                        }
                        let data_len = data.len();
                        if data_len > DATA_CARRIER_SIZE {
                            return Err(Error::msg(format!(
                                "Can't embed data of length {}. Max length: {}",
                                data_len, DATA_CARRIER_SIZE
                            )));
                        }
                        let mut op_return = PushBytesBuf::with_capacity(data_len);
                        op_return.extend_from_slice(&data)?;
                        ScriptBuf::new_op_return(op_return)
                    }
                };

                Ok(TxOut {
                    value: r.amount,
                    script_pubkey,
                })
            })
            .collect();

        let tx_outs = _outputs?;

        let spendable_utxos: Vec<&(String, OwnedOutput)> = available_utxos
            .iter()
            .filter(|(_, o)| o.spend_status == OutputSpendStatus::Unspent)
            .collect();

        // Coin selector
        let candidates: Vec<Candidate> = spendable_utxos
            .iter()
            .map(|(_, o)| Candidate::new(o.amount.to_sat(), TR_KEYSPEND_TXIN_WEIGHT, true)) // We only spend sp outputs, so no need to care about the actual script
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        let change_policy =
            ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, TR_DUST_RELAY_MIN_VALUE); // The min may need to be adjusted, 2 or 3x that would be sensible

        let target = Target {
            fee: TargetFee::from_feerate(FeeRate::from_sat_per_vb(fee_rate as f32)),
            outputs: TargetOutputs::fund_outputs(
                tx_outs
                    .iter()
                    .map(|o| (o.weight().to_wu(), o.value.to_sat())),
            ),
        };

        coin_selector.select_until_target_met(target)?;

        let selected_indices = coin_selector.selected_indices();

        let mut selected_utxos = vec![];
        for i in selected_indices {
            let (outpoint, output) = spendable_utxos[*i];
            selected_utxos.push((OutPoint::from_str(&outpoint)?, output.clone()));
        }

        let change = coin_selector.drain(target, change_policy);

        let change_value = if change.is_some() { change.value } else { 0 };

        if change_value > 0 {
            let change_address = self.sp_receiver.get_change_address();
            recipients.push(Recipient {
                address: RecipientAddress::SpAddress(change_address.try_into()?),
                amount: Amount::from_sat(change_value),
                nb_outputs: 1,
                outputs: vec![],
            });
        };

        let b_spend = match self.spend_key {
            SpendKey::Secret(key) => key,
            SpendKey::Public(_) => return Err(Error::msg("Watch-only wallet, can't spend")),
        };
        let mut outpoints: Vec<(String, u32)> = vec![];
        let mut input_privkeys: Vec<(SecretKey, bool)> = vec![];
        for (outpoint, output) in &selected_utxos {
            outpoints.push((outpoint.txid.to_string(), outpoint.vout));
            let sk = SecretKey::from_slice(&output.tweak)?;
            let signing_key = b_spend.add_tweak(&sk.into())?;
            input_privkeys.push((signing_key, true));
        }

        let partial_secret =
            sp_utils::sending::calculate_partial_secret(&input_privkeys, &outpoints)?;

        Ok(SilentPaymentUnsignedTransaction {
            selected_utxos,
            recipients,
            partial_secret,
            unsigned_tx: None,
            network,
        })
    }

    /// Once we reviewed the temporary transaction state, we can turn it into a transaction
    pub fn finalize_transaction(
        mut unsigned_transaction: SilentPaymentUnsignedTransaction,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        let mut tx_ins = Vec::with_capacity(unsigned_transaction.selected_utxos.len());
        let mut tx_outs = Vec::with_capacity(unsigned_transaction.recipients.len());
        for (outpoint, _) in &unsigned_transaction.selected_utxos {
            let tx_in = TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            };
            tx_ins.push(tx_in);
        }

        // We now need to fill the sp outputs with actual spk
        let sp_addresses: Vec<String> = unsigned_transaction
            .recipients
            .iter()
            .filter_map(|r| match &r.address {
                RecipientAddress::SpAddress(address) => {
                    Some(address.to_string())
                }
                _ => None,
            })
            .collect();

        let sp_address2xonlypubkeys = silentpayments::sending::generate_recipient_pubkeys(
            sp_addresses,
            unsigned_transaction.partial_secret,
        )?;

        for recipient in &unsigned_transaction.recipients {
            let spks = match &recipient.address {
                RecipientAddress::SpAddress(sp_address) => {
                    let pubkeys = sp_address2xonlypubkeys
                        .get(sp_address.to_string().as_str())
                        .ok_or(Error::msg("Unknown sp address"))?;
                    let mut scripts = Vec::with_capacity(pubkeys.len());
                    for pubkey in pubkeys {
                        scripts.push(ScriptBuf::new_p2tr_tweaked(
                            pubkey.dangerous_assume_tweaked(),
                        ));
                    }
                    scripts
                }
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    vec![ScriptBuf::from_bytes(
                        unchecked_address
                            .clone()
                            .require_network(unsigned_transaction.network)?
                            .script_pubkey()
                            .to_bytes(),
                    )]
                }
                RecipientAddress::Data(data) => {
                    if recipient.amount > Amount::from_sat(0) {
                        return Err(Error::msg("Data output must have an amount of 0!"));
                    }
                    let data_len = data.len();
                    if data_len > DATA_CARRIER_SIZE {
                        return Err(Error::msg(format!(
                            "Can't embed data of length {}. Max length: {}",
                            data_len, DATA_CARRIER_SIZE
                        )));
                    }
                    let mut op_return = PushBytesBuf::with_capacity(data_len);
                    op_return.extend_from_slice(&data)?;
                    vec![ScriptBuf::new_op_return(op_return)]
                }
            };
            for spk in spks {
                let tx_out = TxOut {
                    value: recipient.amount,
                    script_pubkey: spk,
                };
                tx_outs.push(tx_out);
            }
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_ins,
            output: tx_outs,
        };
        unsigned_transaction.unsigned_tx = Some(tx);
        Ok(unsigned_transaction)
    }

    fn taproot_sighash<
        T: std::ops::Deref<Target = Transaction> + std::borrow::Borrow<Transaction>,
    >(
        hash_ty: bitcoin::TapSighashType,
        prevouts: &[TxOut],
        input_index: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
    ) -> Result<Message, Error> {
        let prevouts = Prevouts::All(prevouts);

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
        Ok(msg)
    }

    pub fn sign_transaction(
        &self,
        unsigned_tx: SilentPaymentUnsignedTransaction,
        aux_rand: &[u8; 32],
    ) -> Result<Transaction> {
        // TODO check that we have aux_rand, at least that it's not all `0`s
        let b_spend = match self.spend_key {
            SpendKey::Secret(key) => key,
            SpendKey::Public(_) => return Err(Error::msg("Watch-only wallet, can't spend")),
        };

        let to_sign = match unsigned_tx.unsigned_tx.as_ref() {
            Some(tx) => tx,
            None => return Err(Error::msg("Missing unsigned transaction")),
        };

        let mut signed = to_sign.clone();

        let mut cache = SighashCache::new(to_sign);

        let mut prevouts: Vec<TxOut> = Vec::with_capacity(unsigned_tx.selected_utxos.len());

        for (_, utxo) in &unsigned_tx.selected_utxos {
            prevouts.push(TxOut {
                value: utxo.amount,
                script_pubkey: utxo.script.clone(),
            });
        }

        let secp = Secp256k1::signing_only();
        let hash_ty = bitcoin::TapSighashType::Default; // We impose Default for now

        for (i, input) in to_sign.input.iter().enumerate() {
            let tap_leaf_hash: Option<TapLeafHash> = None;


            let msg =
                Self::taproot_sighash(hash_ty, &prevouts, i, &mut cache, tap_leaf_hash)?;

            // Construct the signing key
            let (_, owned_output) = unsigned_tx.selected_utxos.iter()
                .find(|(outpoint, _)| *outpoint == input.previous_output)
                .ok_or(Error::msg(format!("prevout for output {} not in selected utxos", i)))?;

            let tweak = SecretKey::from_slice(owned_output.tweak.as_slice())?;

            let sk = b_spend.add_tweak(&tweak.into())?;

            let keypair = Keypair::from_secret_key(&secp, &sk);

            let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

            let mut witness = Witness::new();
            witness.push(Signature {
                sig,
                hash_ty,
            }.to_vec());

            signed.input[i].witness = witness;
        }

        Ok(signed)
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

    pub fn get_client_fingerprint(&self) -> Result<[u8; 8]> {
        let sp_address: SilentPaymentAddress = self.get_receiving_address().try_into()?;
        let scan_pk = sp_address.get_scan_key();
        let spend_pk = sp_address.get_spend_key();

        // take a fingerprint of the wallet by hashing its keys
        let mut engine = sha256::HashEngine::default();
        engine.write_all(&scan_pk.serialize())?;
        engine.write_all(&spend_pk.serialize())?;
        let hash = sha256::Hash::from_engine(engine);

        // take first 8 bytes as fingerprint
        let mut wallet_fingerprint = [0u8; 8];
        wallet_fingerprint.copy_from_slice(&hash.to_byte_array()[..8]);

        Ok(wallet_fingerprint)
    }
}
