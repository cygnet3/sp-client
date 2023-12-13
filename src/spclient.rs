use bip39::Mnemonic;
use bitcoin::{
    secp256k1::{Secp256k1, SecretKey},
    util::bip32::{DerivationPath, ExtendedPrivKey},
    Network,
};
use once_cell::sync::OnceCell;
use silentpayments::receiving::Receiver;
use std::str::FromStr;

use lazy_static::lazy_static;
use anyhow::Result;

lazy_static! {
    static ref SPCLIENT: OnceCell<SpClient> = OnceCell::new();
}

pub fn create_sp_client(
    scan_sk: SecretKey,
    spend_sk: SecretKey,
    birthday: u32,
    is_testnet: bool,
) -> Result<()> {
    let spclient = SpClient::new(scan_sk, spend_sk, is_testnet, birthday)?;

    let _ = SPCLIENT.set(spclient);
    Ok(())
}

pub fn get_sp_client() -> &'static SpClient {
    SPCLIENT.wait()
}

pub fn get_receiving_address() -> Result<String> {
    let client = get_sp_client();

    let receiver = &client.sp_receiver;

    Ok(receiver.get_receiving_address())
}

pub fn get_birthday() -> u32 {
    let client = get_sp_client();
    let birthday = client.birthday;
    birthday
}

#[derive(Debug)]
pub struct SpClient {
    pub scan_sk: SecretKey,
    pub spend_sk: SecretKey,
    pub sp_receiver: Receiver,
    pub birthday: u32,
}

impl SpClient {
    pub fn new(
        scan_sk: SecretKey,
        spend_sk: SecretKey,
        is_testnet: bool,
        birthday: u32,
    ) -> Result<Self> {
        let secp = Secp256k1::signing_only();
        let spend_pubkey = spend_sk.public_key(&secp);
        let scan_pubkey = scan_sk.public_key(&secp);
        let sp_receiver = Receiver::new(0, scan_pubkey, spend_pubkey, is_testnet)?;

        Ok(Self {
            scan_sk,
            spend_sk,
            sp_receiver,
            birthday,
        })
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
