use std::{collections::HashMap, io::Write, str::FromStr};

use bitcoin::hashes::Hash;
use bitcoin::{
    key::constants::ONE,
    secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
    Network, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use silentpayments::utils as sp_utils;
use silentpayments::Network as SpNetwork;
use silentpayments::{
    bitcoin_hashes::sha256,
    receiving::{Label, Receiver},
    SilentPaymentAddress,
};

use anyhow::{Error, Result};

use crate::constants::NUMS;

use super::SpendKey;

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
        let change_label = Label::new(scan_sk, 0);

        let sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Regtest => SpNetwork::Regtest,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            _ => unreachable!(),
        };

        let sp_receiver = Receiver::new(
            0,
            scan_pubkey,
            (&spend_key).into(),
            change_label,
            sp_network,
        )?;

        Ok(Self {
            scan_sk,
            spend_key,
            sp_receiver,
            network,
        })
    }

    pub fn get_receiving_address(&self) -> SilentPaymentAddress {
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
        let sp_address: SilentPaymentAddress = self.get_receiving_address();
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
