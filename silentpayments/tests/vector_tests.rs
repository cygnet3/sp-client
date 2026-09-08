#![allow(non_snake_case)]
mod common;
#[cfg(test)]
mod tests {
    use secp256k1::{Scalar, Secp256k1, SecretKey};
    use silentpayments::{
        Network, SilentPaymentCode, TransactionInputs, TransactionSharedSecret,
        receiving::Label,
        utils::{
            OutPoint,
            receiving::{PublicTweakData, get_pubkey_from_input, is_p2tr},
            sending::calculate_partial_secret,
        },
    };
    use std::{collections::HashSet, io::Cursor, str::FromStr};

    use silentpayments::receiving::Receiver;

    use silentpayments::sending::generate_recipient_pubkeys;

    use crate::common::{
        structs::TestData,
        utils::{
            self, decode_outputs_to_check, decode_recipients, deser_string_vector,
            verify_and_calculate_signatures,
        },
    };

    const NETWORK: Network = Network::Mainnet;

    #[test]
    fn test_with_test_vectors() {
        let testdata = utils::read_file();

        for test in testdata {
            process_test_case(test);
        }
    }

    fn process_test_case(test_case: TestData) {
        println!("test: {}", test_case.comment);
        let secp = Secp256k1::new();

        let mut sending_outputs: HashSet<String> = HashSet::new();

        for sendingtest in test_case.sending {
            let given = sendingtest.given;
            let expected = sendingtest.expected;
            let outpoints: Vec<OutPoint> = given
                .vin
                .iter()
                .map(|vin| OutPoint::from_txid_and_vout(vin.txid.clone(), vin.vout).unwrap())
                .collect();
            let mut input_priv_keys = Vec::new();
            for input in given.vin {
                let script_sig = hex::decode(&input.scriptSig).unwrap();
                let txinwitness_bytes = hex::decode(&input.txinwitness).unwrap();
                let mut cursor = Cursor::new(&txinwitness_bytes);
                let txinwitness = deser_string_vector(&mut cursor).unwrap();
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();

                match get_pubkey_from_input(&script_sig, &txinwitness, &script_pub_key) {
                    Ok(Some(_pubkey)) => input_priv_keys.push((
                        SecretKey::from_str(&input.private_key).unwrap(),
                        is_p2tr(&script_pub_key),
                    )),
                    Ok(None) => (),
                    Err(e) => panic!("Problem parsing the input: {:?}", e),
                }
            }
            if input_priv_keys.is_empty() {
                continue;
            }

            // we drop the amounts from the test here, since we don't work with amounts
            // the wallet should make sure the amount sent are correct
            let silent_key_material = decode_recipients(&given.recipients);

            let partial_secret = calculate_partial_secret(&input_priv_keys, &outpoints).unwrap();
            let outputs = generate_recipient_pubkeys(silent_key_material, partial_secret).unwrap();

            for output_pubkeys in &outputs {
                for pubkey in output_pubkeys.1 {
                    sending_outputs.insert(hex::encode(pubkey.serialize()));
                }
            }
            assert!(expected.outputs.iter().any(|candidate_set| {
                sending_outputs
                    .iter()
                    .all(|output| candidate_set.contains(output))
            }));
        }

        for receivingtest in test_case.receiving {
            let given = receivingtest.given;
            let expected = receivingtest.expected;

            let b_scan = SecretKey::from_str(&given.key_material.scan_priv_key).unwrap();
            let b_spend = SecretKey::from_str(&given.key_material.spend_priv_key).unwrap();
            let B_spend = b_spend.public_key(&secp);
            let B_scan = b_scan.public_key(&secp);

            let change_label = Label::new(b_scan, 0);
            let mut sp_receiver = Receiver::new(
                silentpayments::SpVersion::ZERO,
                B_scan,
                B_spend,
                change_label,
                NETWORK,
            )
            .unwrap();

            let outputs_to_check = decode_outputs_to_check(&given.outputs);

            let mut inputs = TransactionInputs::new();
            for input in given.vin {
                let script_sig = hex::decode(&input.scriptSig).unwrap();
                let txinwitness_bytes = hex::decode(&input.txinwitness).unwrap();
                let mut cursor = Cursor::new(&txinwitness_bytes);
                let txinwitness = deser_string_vector(&mut cursor).unwrap();
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();
                let outpoint =
                    OutPoint::from_txid_and_vout(input.txid.clone(), input.vout).unwrap();

                match get_pubkey_from_input(&script_sig, &txinwitness, &script_pub_key) {
                    Ok(Some(pubkey)) => {
                        inputs.push(outpoint, script_pub_key, Some(pubkey));
                    }
                    Ok(None) => {
                        inputs.push(outpoint, script_pub_key, None);
                    }
                    Err(e) => panic!("Problem parsing the input: {:?}", e),
                }
            }
            if inputs.input_pubkeys().iter().all(|pk| pk.is_none()) {
                continue;
            }

            for label_int in &given.labels {
                let label = Label::new(b_scan, *label_int);
                sp_receiver.add_label(label).unwrap();
            }

            let mut receiving_codes: HashSet<SilentPaymentCode> = HashSet::new();
            // get receiving code for no label
            receiving_codes.insert(sp_receiver.receiving_code());

            // get receiving codes for every label
            let labels = sp_receiver.list_labels();
            for label in &labels {
                receiving_codes.insert(sp_receiver.receiving_code_for_label(label).unwrap());
            }

            if !&given.labels.contains(&0) {
                receiving_codes.remove(&sp_receiver.change_code());
            }

            let expected_codes: HashSet<SilentPaymentCode> = expected.codes.into_iter().collect();

            // check that the receiving codes generated are equal
            // to the expected codes
            assert_eq!(receiving_codes, expected_codes);

            let tweak_data = PublicTweakData::new(&secp, &inputs).unwrap();
            let ecdh_shared_secret =
                TransactionSharedSecret::new_from_public_tweak_data(&secp, &tweak_data, &b_scan)
                    .unwrap();

            let scanned_outputs_received = sp_receiver
                .scan_transaction(&ecdh_shared_secret, &outputs_to_check)
                .unwrap();

            let key_tweaks: Vec<Scalar> = scanned_outputs_received
                .into_iter()
                .flat_map(|(_, map)| {
                    let mut ret: Vec<Scalar> = vec![];
                    for l in map.into_values() {
                        ret.push(l);
                    }
                    ret
                })
                .collect();

            let res = verify_and_calculate_signatures(key_tweaks, b_spend).unwrap();
            assert!(expected.outputs.len() == res.len());
            assert!(res.iter().all(|output| expected.outputs.contains(output)));
        }
    }
}
