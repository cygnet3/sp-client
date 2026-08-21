//! T3-01 regression: deserializing malformed Receiver JSON must return Err,
//! never panic.
use silentpayments::receiving::{Label, Receiver};
use silentpayments::secp256k1::{Scalar, Secp256k1, SecretKey};
use silentpayments::{Network, SpVersion};

fn valid_receiver_inputs() -> (SecretKey, SecretKey, Label) {
    let scan = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let spend = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let change_label = Label::new(scan, 0);
    (scan, spend, change_label)
}

fn valid_receiver_value() -> serde_json::Value {
    let secp = Secp256k1::new();
    let (scan, spend, change_label) = valid_receiver_inputs();
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

fn deserialize(json: &serde_json::Value) -> Result<Receiver, serde_json::Error> {
    serde_json::from_str(&json.to_string())
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
    assert!(deserialize(&v).is_err());
}

#[test]
fn malformed_scan_pubkey_returns_err() {
    let mut v = valid_receiver_value();
    v["scan_pubkey"] = serde_json::json!(vec![255u8; 33]);
    assert!(deserialize(&v).is_err());
}

#[test]
fn malformed_spend_pubkey_returns_err() {
    let mut v = valid_receiver_value();
    v["spend_pubkey"] = serde_json::json!(vec![0u8; 33]);
    assert!(deserialize(&v).is_err());
}

#[test]
fn malformed_change_label_returns_err() {
    let mut v = valid_receiver_value();
    v["change_label"] = serde_json::json!("deadbeef");
    assert!(deserialize(&v).is_err());
}

#[test]
fn malformed_labels_map_pubkey_returns_err() {
    let mut v = valid_receiver_value();
    // Keep a valid label so the only malformed input is the 33-byte key:
    // the failure must come from PublicKey::from_slice, not label parsing.
    let valid_label = v["change_label"].as_str().unwrap().to_string();
    v["labels"] = serde_json::json!([[vec![199u8; 33], valid_label]]);
    assert!(deserialize(&v).is_err());
}

/// spend_pubkey = -m*G where m is the change-label scalar. Every field
/// parses (valid version, valid 33-byte key, valid label hex), but
/// m*G + spend_pubkey is the point at infinity, so the constructor
/// path (Receiver::new -> add_label) must reject it. Before deserialize
/// was routed through the constructor, this input deserialized cleanly
/// and later panicked in change_code() via .expect().
#[test]
fn negated_label_spend_pubkey_rejected_by_constructor_path() {
    let secp = Secp256k1::new();
    let m_sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let mG = m_sk.public_key(&secp);
    let spend_pubkey = mG.negate(&secp); // -m*G: valid point, invalid key sum
    let scan_pubkey = SecretKey::from_slice(&[1u8; 32]).unwrap().public_key(&secp);
    let change_label = Label::from(Scalar::from_be_bytes(m_sk.secret_bytes()).unwrap());

    let json = serde_json::json!({
        "version": 0,
        "network": "Testnet",
        "scan_pubkey": scan_pubkey.serialize().to_vec(),
        "spend_pubkey": spend_pubkey.serialize().to_vec(),
        "change_label": change_label.as_string(),
        "labels": [],
    });

    let err = deserialize(&json).expect_err("-m*G spend pubkey must be rejected");
    // Pin the constructor-path key-sum check, not a field-parse error.
    assert!(
        err.to_string().contains("sum of public keys"),
        "expected the invalid key sum error, got: {err}",
    );
}

/// A valid-but-wrong key in the labels map of the JSON must be discarded:
/// add_label recomputes the key as m*G from the label. Under the old
/// field-copy the wrong key was stored verbatim and a scan would look it
/// up in labels.get() and silently miss outputs for that label.
#[test]
fn wrong_labels_map_key_is_recomputed_from_label() {
    let secp = Secp256k1::new();
    let (b_scan, b_spend, change_label) = valid_receiver_inputs();
    let scan_pubkey = b_scan.public_key(&secp);
    let spend_pubkey = b_spend.public_key(&secp);

    let label = Label::new(b_scan, 1);
    let mG = SecretKey::from_slice(&label.as_inner().to_be_bytes())
        .unwrap()
        .public_key(&secp);
    assert_ne!(
        mG, spend_pubkey,
        "crafted key must differ from the recomputed one",
    );

    // Crafted key in the JSON: spend_pubkey itself — a valid on-curve key,
    // just not m*G. The label value is valid and composable with spend_pubkey.
    let mut json = valid_receiver_value();
    json["labels"] = serde_json::json!([[spend_pubkey.serialize().to_vec(), label.as_string()]]);

    let deserialized =
        deserialize(&json).expect("valid label with wrong key must still deserialize");

    // Ground truth via the constructor API: the stored key must be m*G.
    let mut expected = Receiver::new(
        SpVersion::ZERO,
        scan_pubkey,
        spend_pubkey,
        change_label,
        Network::Testnet,
    )
    .unwrap();
    assert!(expected.add_label(label.clone()).unwrap());
    assert_eq!(deserialized, expected);

    // User-visible consequence: the label address derives from m*G + B_spend,
    // not from the wrong key carried in the JSON.
    let expected_m_pubkey = mG.combine(&spend_pubkey).unwrap();
    let addr = deserialized.receiving_code_for_label(&label).unwrap();
    assert_eq!(addr.m_pubkey(), expected_m_pubkey);
}

/// change_code() on a deserialized receiver must agree with the
/// receiver built via the constructor API: for valid JSON the .expect()
/// panic path in change_code() is unreachable, and the whole
/// struct round-trips the labels map exactly.
#[test]
fn deserialized_receiver_matches_construction() {
    let secp = Secp256k1::new();
    let (b_scan, b_spend, change_label) = valid_receiver_inputs();
    let json = valid_receiver_value();

    let deserialized = deserialize(&json).expect("valid JSON must deserialize");

    let expected = Receiver::new(
        SpVersion::ZERO,
        b_scan.public_key(&secp),
        b_spend.public_key(&secp),
        change_label,
        Network::Testnet,
    )
    .unwrap();
    assert_eq!(deserialized, expected);
    assert_eq!(deserialized.change_code(), expected.change_code());
}
