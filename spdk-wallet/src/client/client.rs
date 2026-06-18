use std::{collections::HashMap, io::Write};

use bitcoin::{
    Network,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use serde::{Deserialize, Serialize};
use silentpayments::{Network as SpNetwork, SilentPaymentCode, SpVersion, TransactionSharedSecret};
use silentpayments::{bitcoin_hashes::Hash, utils::receiving::PublicTweakData};
use silentpayments::{
    bitcoin_hashes::sha256,
    receiving::{Label, Receiver},
};

use anyhow::{Error, Result};

use super::SpendKey;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SpClient {
    scan_sk: SecretKey,
    spend_key: SpendKey,
    pub sp_receiver: Receiver,
    network: Network,
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
            SpVersion::ZERO,
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

    pub fn receiving_code(&self) -> SilentPaymentCode {
        self.sp_receiver.receiving_code()
    }

    pub fn scan_key(&self) -> SecretKey {
        self.scan_sk
    }

    pub fn spend_key(&self) -> SpendKey {
        self.spend_key.clone()
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn try_secret_spend_key(&self) -> Result<SecretKey> {
        match self.spend_key {
            SpendKey::Public(_) => Err(Error::msg("Don't have secret key")),
            SpendKey::Secret(sk) => Ok(sk),
        }
    }

    pub fn script_to_secret_map(
        &self,
        tweak_data_vec: Vec<PublicKey>,
    ) -> Result<HashMap<[u8; 34], TransactionSharedSecret>> {
        // if using rayon feature, import the preludes
        #[cfg(feature = "rayon")]
        use rayon::prelude::*;

        let b_scan = &self.scan_key();
        let secp = Secp256k1::signing_only();

        // parallel iterator using rayon
        #[cfg(feature = "rayon")]
        let tweak_data_iterator = tweak_data_vec.into_par_iter();

        // regular iterator
        #[cfg(not(feature = "rayon"))]
        let tweak_data_iterator = tweak_data_vec.into_iter();

        let items: Result<Vec<_>> = tweak_data_iterator
            .map(|tweak| {
                let tweak_data = PublicTweakData::new_unchecked(tweak);
                let secret = TransactionSharedSecret::new_from_public_tweak_data(
                    &secp,
                    &tweak_data,
                    b_scan,
                )?;
                let spks = self
                    .sp_receiver
                    .script_pubkeys_from_shared_secret(&secret)?;

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

    pub fn client_fingerprint(&self) -> Result<[u8; 8]> {
        let sp_code: SilentPaymentCode = self.receiving_code();
        let scan_pk = sp_code.scan_key();
        let spend_pk = sp_code.m_pubkey();

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

impl Drop for SpClient {
    fn drop(&mut self) {
        // Erase the scan key before dropping; the spend key is erased
        // by SpendKey's own Drop impl.
        self.scan_sk.non_secure_erase();
    }
}
