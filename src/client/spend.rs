use std::str::FromStr;

use bdk_coin_select::{
    Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, Target, TargetFee, TargetOutputs,
    TR_DUST_RELAY_MIN_VALUE,
};
use bitcoin::{
    absolute::LockTime,
    key::TapTweak,
    script::PushBytesBuf,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey, ThirtyTwoByteHash},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    transaction::Version,
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Witness,
};

use silentpayments::utils as sp_utils;
use silentpayments::{Network as SpNetwork, SilentPaymentAddress};

use anyhow::{Error, Result};

use crate::constants::{DATA_CARRIER_SIZE, NUMS};

use super::{
    OutputSpendStatus, OwnedOutput, Recipient, RecipientAddress, SilentPaymentUnsignedTransaction,
    SpClient,
};

impl SpClient {
    // For now it's only suitable for wallet that spends only silent payments outputs that it owns
    pub fn create_new_transaction(
        &self,
        available_utxos: Vec<(OutPoint, OwnedOutput)>,
        mut recipients: Vec<Recipient>,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        // check that all available outputs are unspent
        if available_utxos
            .iter()
            .any(|(_, o)| o.spend_status != OutputSpendStatus::Unspent)
        {
            return Err(Error::msg(format!("All outputs must be unspent")));
        }

        // used to estimate the size of a taproot output
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)
                .expect("NUMS is always valid")
                .dangerous_assume_tweaked(),
        );

        let address_sp_network = match network {
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
                RecipientAddress::SpAddress(sp_address) => {
                    if sp_address.get_network() != address_sp_network {
                        return Err(Error::msg(format!(
                            "Wrong network for address {}",
                            sp_address
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
                        op_return.extend_from_slice(&data)?;
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
            .map(|(_, o)| Candidate::new_tr_keyspend(o.amount.to_sat()))
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

        // if there is change, add a return address to the list of recipients
        let change = coin_selector.drain(target, change_policy);
        let change_value = if change.is_some() { change.value } else { 0 };
        if change_value > 0 {
            let change_address =
                SilentPaymentAddress::try_from(self.sp_receiver.get_change_address())?;
            recipients.push(Recipient {
                address: RecipientAddress::SpAddress(change_address),
                amount: Amount::from_sat(change_value),
            });
        };

        let partial_secret = self.get_partial_secret_for_selected_utxos(&selected_utxos)?;

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
        available_utxos: Vec<(OutPoint, OwnedOutput)>,
        recipient: RecipientAddress,
        fee_rate: f32,
        network: Network,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        // check that all available outputs are unspent
        if available_utxos
            .iter()
            .any(|(_, o)| o.spend_status != OutputSpendStatus::Unspent)
        {
            return Err(Error::msg(format!("All outputs must be unspent")));
        }

        // used to estimate the size of a taproot output
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)
                .expect("NUMS is always valid")
                .dangerous_assume_tweaked(),
        );

        let address_sp_network = match network {
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
            RecipientAddress::SpAddress(sp_address) => {
                if sp_address.get_network() != address_sp_network {
                    return Err(Error::msg(format!(
                        "Wrong network for address {}",
                        sp_address
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
            .map(|(_, o)| Candidate::new_tr_keyspend(o.amount.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        // we force a change, by having the min_value be set to 0
        let change_policy = ChangePolicy::min_value(drain_output, 0);

        let target = Target {
            fee: TargetFee::from_feerate(FeeRate::from_sat_per_vb(fee_rate)),
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

        let partial_secret = self.get_partial_secret_for_selected_utxos(&available_utxos)?;

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

        let sp_addresses: Vec<SilentPaymentAddress> = unsigned_transaction
            .recipients
            .iter()
            .filter_map(|r| match &r.address {
                RecipientAddress::SpAddress(sp_address) => Some(sp_address.to_owned()),
                _ => None,
            })
            .collect();

        let sp_address2xonlypubkeys = silentpayments::sending::generate_recipient_pubkeys(
            sp_addresses,
            unsigned_transaction.partial_secret,
        )?;

        let tx_outs = unsigned_transaction
            .recipients
            .iter()
            .map(|recipient| match &recipient.address {
                RecipientAddress::SpAddress(s) => {
                    // We now need to fill the sp outputs with actual spk
                    let pubkeys = sp_address2xonlypubkeys
                        .get(s)
                        .ok_or(Error::msg("Unknown sp address"))?;

                    // we currently only allow having 1 output per silent payment address
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
                    op_return.extend_from_slice(&data)?;
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
        let msg = Message::from_digest(sighash.into_32());
        Ok(msg)
    }

    pub fn sign_transaction(
        &self,
        unsigned_tx: SilentPaymentUnsignedTransaction,
        aux_rand: &[u8; 32],
    ) -> Result<Transaction> {
        // TODO check that we have aux_rand, at least that it's not all `0`s
        let b_spend = self.try_get_secret_spend_key()?;

        let to_sign = match unsigned_tx.unsigned_tx.as_ref() {
            Some(tx) => tx,
            None => return Err(Error::msg("Missing unsigned transaction")),
        };

        let mut signed = to_sign.clone();

        let mut cache = SighashCache::new(to_sign);

        let prevouts: Vec<_> = unsigned_tx
            .selected_utxos
            .iter()
            .map(|(_, owned_output)| TxOut {
                value: owned_output.amount,
                script_pubkey: owned_output.script.clone(),
            })
            .collect();

        let secp = Secp256k1::signing_only();
        let hash_ty = bitcoin::TapSighashType::Default; // We impose Default for now

        for (i, input) in to_sign.input.iter().enumerate() {
            let tap_leaf_hash: Option<TapLeafHash> = None;

            let msg = Self::taproot_sighash(hash_ty, &prevouts, i, &mut cache, tap_leaf_hash)?;

            // Construct the signing key
            let (_, owned_output) = unsigned_tx
                .selected_utxos
                .iter()
                .find(|(outpoint, _)| *outpoint == input.previous_output)
                .ok_or(Error::msg(format!(
                    "prevout for output {} not in selected utxos",
                    i
                )))?;

            let tweak = SecretKey::from_slice(owned_output.tweak.as_slice())?;

            let sk = b_spend.add_tweak(&tweak.into())?;

            let keypair = Keypair::from_secret_key(&secp, &sk);

            let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

            let mut witness = Witness::new();
            witness.push(Signature { sig, hash_ty }.to_vec());

            signed.input[i].witness = witness;
        }

        Ok(signed)
    }

    pub fn get_partial_secret_for_selected_utxos(
        &self,
        selected_utxos: &[(OutPoint, OwnedOutput)],
    ) -> Result<SecretKey> {
        let b_spend = self.try_get_secret_spend_key()?;

        let outpoints: Vec<_> = selected_utxos
            .iter()
            .map(|(outpoint, _)| (outpoint.txid.to_string(), outpoint.vout))
            .collect();
        let input_privkeys = selected_utxos
            .iter()
            .map(|(_, output)| {
                let sk = SecretKey::from_slice(&output.tweak)?;
                let signing_key = b_spend.add_tweak(&sk.into())?;
                Ok((signing_key, true))
            })
            .collect::<Result<Vec<_>>>()?;

        let partial_secret =
            sp_utils::sending::calculate_partial_secret(&input_privkeys, &outpoints)?;

        Ok(partial_secret)
    }
}
