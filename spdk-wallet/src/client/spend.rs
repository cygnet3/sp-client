use std::str::FromStr;

use anyhow::{Error, Result};
use bdk_coin_select::{
    Candidate, ChangePolicy, CoinSelector, DrainWeights, TR_DUST_RELAY_MIN_VALUE, Target,
    TargetFee, TargetOutputs,
};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::Signature;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Witness,
};
use silentpayments::Network as SpNetwork;
use silentpayments::utils::sending::PartialSecret;
use silentpayments::{SilentPaymentCode, utils as sp_utils};

use spdk_core::constants::{DATA_CARRIER_SIZE, NUMS};
use spdk_core::updater::DiscoveredOutput;

use super::{FeeRate, Recipient, RecipientAddress, SilentPaymentUnsignedTransaction, SpClient};

impl SpClient {
    // For now it's only suitable for wallet that spends only silent payments outputs that it owns
    pub fn create_new_transaction(
        &self,
        available_utxos: Vec<(OutPoint, DiscoveredOutput)>,
        mut recipients: Vec<Recipient>,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        // used to estimate the size of a taproot output
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)
                .expect("NUMS is always valid")
                .dangerous_assume_tweaked(),
        );

        let sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            Network::Regtest => SpNetwork::Regtest,
            _ => unreachable!(),
        };

        let tx_outs = recipients
            .iter()
            .map(|recipient| match &recipient.address {
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    let value = recipient.amount;
                    let script_pubkey = unchecked_address
                        .clone()
                        .require_network(network)?
                        .script_pubkey();

                    Ok(TxOut {
                        value,
                        script_pubkey,
                    })
                }
                RecipientAddress::SpCode(sp_code) => {
                    if sp_code.network() != sp_network {
                        return Err(Error::msg(format!(
                            "Wrong network for silent payment code {}",
                            sp_code
                        )));
                    }

                    Ok(TxOut {
                        value: recipient.amount,
                        script_pubkey: placeholder_spk.clone(),
                    })
                }
                RecipientAddress::Data(data) => {
                    let value = recipient.amount;
                    let data_len = data.len();
                    if value > Amount::from_sat(0) {
                        Err(Error::msg("Data output must have an amount of 0!"))
                    } else if data_len > DATA_CARRIER_SIZE {
                        Err(Error::msg(format!(
                            "Can't embed data of length {}. Max length: {}",
                            data_len, DATA_CARRIER_SIZE
                        )))
                    } else {
                        let mut op_return = PushBytesBuf::with_capacity(data_len);
                        op_return.extend_from_slice(data)?;
                        let script_pubkey = ScriptBuf::new_op_return(op_return);

                        Ok(TxOut {
                            value,
                            script_pubkey,
                        })
                    }
                }
            })
            .collect::<Result<Vec<TxOut>>>()?;

        // as a silent payment wallet, we only spend taproot outputs
        let candidates: Vec<Candidate> = available_utxos
            .iter()
            .map(|(_, o)| Candidate::new_tr_keyspend(o.value.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        // The min may need to be adjusted, 2 or 3x that would be sensible
        let change_policy =
            ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, TR_DUST_RELAY_MIN_VALUE);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: TargetOutputs::fund_outputs(
                tx_outs
                    .iter()
                    .map(|o| (o.weight().to_wu(), o.value.to_sat())),
            ),
        };

        coin_selector.select_until_target_met(target)?;

        // get the utxos that have been chosen by the coin selector
        let selected_indices = coin_selector.selected_indices();
        let mut selected_utxos = vec![];
        for i in selected_indices {
            let (outpoint, output) = &available_utxos[*i];
            selected_utxos.push((*outpoint, output.clone()));
        }

        // if there is change, add a change code to the list of recipients
        let change = coin_selector.drain(target, change_policy);
        let change_value = if change.is_some() { change.value } else { 0 };
        if change_value > 0 {
            recipients.push(Recipient {
                address: RecipientAddress::SpCode(self.sp_receiver.change_code()),
                amount: Amount::from_sat(change_value),
            });
        };

        let partial_secret = self.partial_secret_for_selected_utxos(&selected_utxos)?;

        Ok(SilentPaymentUnsignedTransaction {
            selected_utxos,
            recipients,
            partial_secret,
            unsigned_tx: None,
            network,
        })
    }

    /// A drain transaction spends all the available utxos to a single RecipientAddress.
    pub fn create_drain_transaction(
        &self,
        available_utxos: Vec<(OutPoint, DiscoveredOutput)>,
        recipient: RecipientAddress,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        // used to estimate the size of a taproot output
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)
                .expect("NUMS is always valid")
                .dangerous_assume_tweaked(),
        );

        let sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            Network::Regtest => SpNetwork::Regtest,
            _ => unreachable!(),
        };

        let output = match &recipient {
            RecipientAddress::LegacyAddress(address) => Ok(TxOut {
                value: Amount::ZERO,
                script_pubkey: address.clone().require_network(network)?.script_pubkey(),
            }),
            RecipientAddress::SpCode(sp_code) => {
                if sp_code.network() != sp_network {
                    return Err(Error::msg(format!(
                        "Wrong network for silent payment code {}",
                        sp_code
                    )));
                }

                Ok(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: placeholder_spk.clone(),
                })
            }
            RecipientAddress::Data(_) => Err(Error::msg("Draining to OP_RETURN not allowed")),
        }?;

        // for a drain transaction, we have no target outputs.
        // instead, we register the recipient as the drain output.
        let target_outputs = TargetOutputs {
            value_sum: 0,
            weight_sum: 0,
            n_outputs: 0,
        };

        let drain_output = DrainWeights {
            output_weight: output.weight().to_wu(),
            spend_weight: 0,
            n_outputs: 1,
        };

        // as a silent payment wallet, we only spend taproot outputs
        let candidates: Vec<Candidate> = available_utxos
            .iter()
            .map(|(_, o)| Candidate::new_tr_keyspend(o.value.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        // we force a change, by having the min_value be set to 0
        let change_policy = ChangePolicy::min_value(drain_output, 0);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: target_outputs,
        };

        // for a drain transaction, we select all avaliable inputs
        coin_selector.select_all();

        let change = coin_selector.drain(target, change_policy);

        if change.is_none() {
            return Err(Error::msg("No funds available"));
        }

        let recipients = vec![Recipient {
            address: recipient,
            amount: Amount::from_sat(change.value),
        }];

        let partial_secret = self.partial_secret_for_selected_utxos(&available_utxos)?;

        Ok(SilentPaymentUnsignedTransaction {
            selected_utxos: available_utxos,
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
        let tx_ins: Vec<TxIn> = unsigned_transaction
            .selected_utxos
            .iter()
            .map(|(outpoint, _)| TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect();

        let recipient_codes: Vec<SilentPaymentCode> = unsigned_transaction
            .recipients
            .iter()
            .filter_map(|r| match &r.address {
                RecipientAddress::SpCode(sp_code) => Some(*sp_code),
                _ => None,
            })
            .collect();

        let sp_key_material2xonlypubkeys = silentpayments::sending::generate_recipient_pubkeys(
            recipient_codes,
            unsigned_transaction.partial_secret,
        )?;

        let tx_outs = unsigned_transaction
            .recipients
            .iter()
            .map(|recipient| match &recipient.address {
                RecipientAddress::SpCode(sp_code) => {
                    // We now need to fill the sp outputs with actual spk
                    let pubkeys = sp_key_material2xonlypubkeys
                        .get(sp_code)
                        .ok_or(Error::msg("Unknown silent payment key material"))?;

                    // we currently only allow having 1 output per silent payment key material
                    // note: when changing this, it should also be accounted for in 'create_new_transaction'
                    if pubkeys.len() == 1 {
                        let pubkey = pubkeys[0];
                        let script = ScriptBuf::new_p2tr_tweaked(pubkey.dangerous_assume_tweaked());
                        Ok(TxOut {
                            value: recipient.amount,
                            script_pubkey: script,
                        })
                    } else {
                        Err(Error::msg("multiple outputs not supported"))
                    }
                }
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    let script = unchecked_address
                        .clone()
                        .require_network(unsigned_transaction.network)?
                        .script_pubkey();

                    Ok(TxOut {
                        value: recipient.amount,
                        script_pubkey: script,
                    })
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
                    op_return.extend_from_slice(data)?;
                    let script = ScriptBuf::new_op_return(op_return);
                    Ok(TxOut {
                        value: recipient.amount,
                        script_pubkey: script,
                    })
                }
            })
            .collect::<Result<Vec<TxOut>>>()?;

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
        let msg = Message::from_digest(sighash.to_byte_array());
        Ok(msg)
    }

    pub fn sign_transaction(
        &self,
        unsigned_tx: SilentPaymentUnsignedTransaction,
        aux_rand: &[u8; 32],
    ) -> Result<Transaction> {
        // TODO check that we have aux_rand, at least that it's not all `0`s
        let b_spend = self.try_secret_spend_key()?;

        let to_sign = match unsigned_tx.unsigned_tx.as_ref() {
            Some(tx) => tx,
            None => return Err(Error::msg("Missing unsigned transaction")),
        };

        let mut signed = to_sign.clone();

        let mut cache = SighashCache::new(to_sign);

        let prevouts: Vec<_> = unsigned_tx
            .selected_utxos
            .iter()
            .map(|(_, output)| TxOut {
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            })
            .collect();

        let secp = Secp256k1::signing_only();
        let sighash_type = bitcoin::TapSighashType::Default; // We impose Default for now

        for (i, input) in to_sign.input.iter().enumerate() {
            let tap_leaf_hash: Option<TapLeafHash> = None;

            let msg = Self::taproot_sighash(sighash_type, &prevouts, i, &mut cache, tap_leaf_hash)?;

            // Construct the signing key
            let (_, owned_output) = unsigned_tx
                .selected_utxos
                .iter()
                .find(|(outpoint, _)| *outpoint == input.previous_output)
                .ok_or(Error::msg(format!(
                    "prevout for output {} not in selected utxos",
                    i
                )))?;

            let sk = b_spend.add_tweak(&owned_output.tweak)?;

            let keypair = Keypair::from_secret_key(&secp, &sk);

            let signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

            let mut witness = Witness::new();
            witness.push(
                Signature {
                    signature,
                    sighash_type,
                }
                .to_vec(),
            );

            signed.input[i].witness = witness;
        }

        Ok(signed)
    }

    pub fn partial_secret_for_selected_utxos(
        &self,
        selected_utxos: &[(OutPoint, DiscoveredOutput)],
    ) -> Result<PartialSecret> {
        let b_spend = self.try_secret_spend_key()?;

        let outpoints = selected_utxos
            .iter()
            .map(|(outpoint, _)| {
                Ok(sp_utils::OutPoint::from_txid_and_vout(
                    outpoint.txid.to_string(),
                    outpoint.vout,
                )?)
            })
            .collect::<Result<Vec<sp_utils::OutPoint>>>()?;
        let input_privkeys = selected_utxos
            .iter()
            .map(|(_, output)| Ok((b_spend.add_tweak(&output.tweak)?, true)))
            .collect::<Result<Vec<_>>>()?;

        let partial_secret =
            sp_utils::sending::calculate_partial_secret(&input_privkeys, &outpoints)?;

        Ok(partial_secret)
    }
}
