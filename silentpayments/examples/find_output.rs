use std::{env, error::Error, str::FromStr};

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::Secp256k1 as BtcSecp256k1;
use bitcoin::{Network, PrivateKey, ScriptBuf, Transaction};
use bitcoin_hashes::hex::FromHex;

use silentpayments::utils::{TEST_SCAN_PATH, TEST_SPEND_PATH};
// Import types from the silentpayments library
use silentpayments::receiving::{Label, Receiver};
use silentpayments::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use silentpayments::utils::OutPoint;
use silentpayments::utils::receiving::{PublicTweakData, get_pubkey_from_input};
use silentpayments::{Network as SpNetwork, SpVersion, TransactionInputs, TransactionSharedSecret};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let m = Mnemonic::from_str(args.get(1).unwrap())?;
    let tx_hex = args.get(2).unwrap();
    let spks: Vec<&str> = args.get(3).unwrap().split_whitespace().collect();

    let tx: Transaction = deserialize(Vec::from_hex(tx_hex)?.as_slice())?;
    assert!(tx.input.len() == spks.len());

    let master_key = Xpriv::new_master(bitcoin::Network::Signet, &m.to_seed(""))?;

    // Define the scan and spend paths for the wallet
    let scan_path = DerivationPath::from_str(TEST_SCAN_PATH).unwrap();
    let spend_path = DerivationPath::from_str(TEST_SPEND_PATH).unwrap();

    let btc_secp = BtcSecp256k1::signing_only();
    let secp = Secp256k1::new();

    let scan_privkey = master_key.derive_priv(&btc_secp, &scan_path)?.private_key;
    let spend_privkey = master_key.derive_priv(&btc_secp, &spend_path)?.private_key;
    let scan_sk = SecretKey::from_slice(&scan_privkey.secret_bytes())?;
    let spend_sk = SecretKey::from_slice(&spend_privkey.secret_bytes())?;

    let change_label = Label::new(scan_sk, 0);

    let receiver = Receiver::new(
        SpVersion::ZERO,
        scan_sk.public_key(&secp),
        spend_sk.public_key(&secp),
        change_label,
        SpNetwork::Testnet,
    )?;

    let mut inputs = TransactionInputs::new();
    for (i, input) in tx.input.iter().enumerate() {
        let prevout = &input.previous_output;
        let outpoint =
            OutPoint::from_txid_and_vout(prevout.txid.to_string(), prevout.vout).unwrap();
        let spk = ScriptBuf::from_hex(spks.get(i).unwrap())?;
        let pubkey = get_pubkey_from_input(
            input.script_sig.as_bytes(),
            &input.witness.to_vec(),
            spk.as_bytes(),
        )?;
        inputs.push(outpoint, spk.to_bytes(), pubkey);
    }

    let tweak_data = PublicTweakData::new(&secp, &inputs)?;
    let ecdh_shared_secret =
        TransactionSharedSecret::new_from_public_tweak_data(&secp, &tweak_data, &scan_sk)?;

    let pubkeys_to_check: Vec<_> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .map(|o| {
            XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..])
                .expect("P2tr output should have a valid xonly key")
        })
        .collect();

    let my_outputs = receiver.scan_transaction(&ecdh_shared_secret, &pubkeys_to_check)?;

    println!("Found {} output(s)", my_outputs.len());

    for (label, key_map) in my_outputs {
        println!("Found {} output(s) with label {:?}", key_map.len(), label);
        for (xonly, sk) in key_map {
            let spending_key = spend_sk.add_tweak(&sk)?;
            let wif = PrivateKey::from_slice(&spending_key.secret_bytes(), Network::Signet)
                .unwrap()
                .to_wif();
            println!("Private key to spend output with key {}: {}", xonly, wif);
            println!("Descriptor to import in Bitcoin Core: rawtr({})", wif);
        }
    }

    Ok(())
}
