use bitcoin::{
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    util::bip32::{DerivationPath, ExtendedPrivKey},
};
use once_cell::sync::OnceCell;
use silentpayments::receiving::Receiver;
use std::str::FromStr;

use lazy_static::lazy_static;
use anyhow::Result;

const BIRTHDAY: u32 = 160000;
const IS_TESTNET: bool = true;
const SCAN_SK: &str = "0aa78769a8aada0e7df0a8710e4c740266c4b1d050e12d9703848fb03f6f1835";
const SPEND_PK: &str = "02b4d7047ed9ec51b9f2ad9aad675495ac18f33f71ec9f777dd7133784919a71e0";

lazy_static! {
    static ref SPCLIENT: OnceCell<SpClient> = OnceCell::new();
}

pub fn create_sp_client() -> Result<()> {
    let birthday = BIRTHDAY;
    let is_testnet = IS_TESTNET;
    // let xprv_str =  XPRV_STR;
    // let xprv: ExtendedPrivKey = ExtendedPrivKey::from_str(xprv_str).unwrap();

    let scan_sk = SecretKey::from_str(SCAN_SK)?;
    let spend_pk = PublicKey::from_str(SPEND_PK)?;

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

pub fn get_birthday() -> Result<u32> {
    let client = get_sp_client();
    let birthday = client.birthday;
    Ok(birthday)
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

