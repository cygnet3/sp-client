//! T3-01 regression: deserializing malformed Receiver JSON must return Err,
//! never panic.
use silentpayments::receiving::{Label, Receiver};
use silentpayments::secp256k1::{Secp256k1, SecretKey};
use silentpayments::{Network, SpVersion};

fn valid_receiver_value() -> serde_json::Value {
    let secp = Secp256k1::new();
    let scan = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let spend = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let change_label = Label::new(scan, 0);
    let receiver = Receiver::new(
        SpVersion::ZERO,
        scan.public_key(&secp),
        spend.public_key(&secp),
        change_label,
        Network::Testnet,
    )
    .unwrap();
    serde_json::to_value(&receiver).unwrap()
}

#[test]
fn valid_receiver_json_roundtrips() {
    let v = valid_receiver_value();
    let ok = serde_json::to_string(&v).unwrap();
    let _: Receiver = serde_json::from_str(&ok).expect("valid JSON must deserialize");
}

#[test]
fn malformed_version_returns_err() {
    let mut v = valid_receiver_value();
    v["version"] = serde_json::json!(7);
    assert!(serde_json::from_str::<Receiver>(&v.to_string()).is_err());
}

#[test]
fn malformed_scan_pubkey_returns_err() {
    let mut v = valid_receiver_value();
    v["scan_pubkey"] = serde_json::json!(vec![255u8; 33]);
    assert!(serde_json::from_str::<Receiver>(&v.to_string()).is_err());
}

#[test]
fn malformed_spend_pubkey_returns_err() {
    let mut v = valid_receiver_value();
    v["spend_pubkey"] = serde_json::json!(vec![0u8; 33]);
    assert!(serde_json::from_str::<Receiver>(&v.to_string()).is_err());
}

#[test]
fn malformed_change_label_returns_err() {
    let mut v = valid_receiver_value();
    v["change_label"] = serde_json::json!("deadbeef");
    assert!(serde_json::from_str::<Receiver>(&v.to_string()).is_err());
}

#[test]
fn malformed_labels_map_pubkey_returns_err() {
    let mut v = valid_receiver_value();
    // Keep a valid label so the only malformed input is the 33-byte key:
    // the failure must come from PublicKey::from_slice, not label parsing.
    let valid_label = v["change_label"].as_str().unwrap().to_string();
    v["labels"] = serde_json::json!([[vec![199u8; 33], valid_label]]);
    assert!(serde_json::from_str::<Receiver>(&v.to_string()).is_err());
}
