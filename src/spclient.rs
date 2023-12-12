use bitcoin::{
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    util::bip32::{DerivationPath, ExtendedPrivKey},
};
use once_cell::sync::OnceCell;
use silentpayments::receiving::Receiver;
use std::str::FromStr;

use lazy_static::lazy_static;
use anyhow::Result;

lazy_static! {
    static ref SPCLIENT: OnceCell<SpClient> = OnceCell::new();
}

pub fn create_sp_client(scan_sk: String, spend_pk: String, birthday: u32, is_testnet: bool) -> Result<()> {
    let scan_sk = SecretKey::from_str(&scan_sk)?;
    let spend_pk = PublicKey::from_str(&spend_pk)?;

    let spclient = SpClient::new(scan_sk, spend_pk, is_testnet, birthday)?;

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
    pub scan_privkey: SecretKey,
    pub spend_pubkey: PublicKey,
    pub sp_receiver: Receiver,
    pub birthday: u32,
}

impl SpClient {
    pub fn new(scan_privkey: SecretKey, spend_pubkey: PublicKey, is_testnet: bool, birthday: u32) -> Result<Self> {
        let secp = Secp256k1::new();
        let scan_pubkey = scan_privkey.public_key(&secp);
        let sp_receiver = Receiver::new(0, scan_pubkey, spend_pubkey, is_testnet)?;

        Ok(Self {
            scan_privkey,
            spend_pubkey,
            sp_receiver,
            birthday,
        })
    }
}


fn _get_keys_from_xprv(xprv: ExtendedPrivKey, is_testnet: bool) -> Result<(SecretKey, PublicKey, PublicKey)> {
    let (scan_path, spend_path) = match is_testnet {
        true => ("m/352h/1h/0h/1h/0", "m/352h/1h/0h/0h/0"),
        false => ("m/352h/0h/0h/1h/0", "m/352h/0h/0h/0h/0"),
    };

    let secp = Secp256k1::new();
    let scan_path: DerivationPath = DerivationPath::from_str(scan_path)?;
    let spend_path: DerivationPath = DerivationPath::from_str(spend_path)?;
    let scan_privkey = xprv.derive_priv(&secp, &scan_path)?.private_key;
    let spend_privkey = xprv.derive_priv(&secp, &spend_path)?.private_key;

    let secp = Secp256k1::new();
    let scan_pubkey = scan_privkey.public_key(&secp);
    let spend_pubkey = spend_privkey.public_key(&secp);

    Ok((scan_privkey, scan_pubkey, spend_pubkey))
}

