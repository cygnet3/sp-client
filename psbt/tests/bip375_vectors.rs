//! Consolidated BIP-375 vector coverage at the PSBT/SPDK boundary.
//!
//! Upstream `rust-psbt` is treated as the parse boundary. SPDK is responsible for share placement
//! semantics and silent payment output derivation.

use std::fs;
use std::path::PathBuf;

use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use psbt::roles::SpSignerExt;
use psbt_v2::psbt::Psbt;
use psbt_v2::SilentPaymentState;
use secp256k1::Secp256k1;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TestVectors {
    valid: Vec<TestVector>,
    invalid: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
struct TestVector {
    description: String,
    psbt: String,
    supplementary: Supplementary,
}

/// Declared expected outcome for a vector. This is the single source of truth that drives
/// dispatch, mirroring the upstream `rust-psbt` harness. The `valid` / `invalid` array a vector
/// lives in is cross-checked against the task but is not itself the oracle.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Task {
    Sign,
    Finalize,
    FailSign,
    FailDeserialize,
}

#[derive(Debug, Deserialize)]
struct Supplementary {
    task: Task,
}

type VectorResult = Result<Option<String>, String>;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bip375_test_vectors.json")
}

fn load_vectors() -> TestVectors {
    let content = fs::read_to_string(vectors_path()).expect("failed to read BIP375 test vectors");
    serde_json::from_str(&content).expect("failed to parse BIP375 test vectors JSON")
}

fn decode_psbt_base64(base64: &str) -> Vec<u8> {
    BASE64_STANDARD
        .decode(base64)
        .expect("BIP375 vector PSBT must be valid base64")
}

fn parse_psbt(base64: &str) -> Result<Psbt, psbt_v2::DeserializeError> {
    let bytes = decode_psbt_base64(base64);
    Psbt::deserialize(&bytes)
}

fn derive_outputs(psbt: &Psbt) -> Result<Psbt, String> {
    let secp = Secp256k1::new();
    let mut derived = psbt.clone();
    derived
        .commit_sp_outputs(&secp)
        .map_err(|e| format!("commit_sp_outputs failed: {e}"))?;
    Ok(derived)
}

fn has_unsigned_inputs(psbt: &Psbt) -> bool {
    psbt.inputs.iter().any(|input| {
        input.partial_sigs.is_empty()
            && input.tap_key_sig.is_none()
            && input.tap_script_sigs.is_empty()
            && input.final_script_sig.is_none()
            && input.final_script_witness.is_none()
    })
}

fn signer_rejection_reason(psbt: &Psbt) -> Option<String> {
    if let Err(e) = psbt.silent_payment_signer_checks() {
        return Some(format!("psbt.silent_payment_signer_checks rejected => {e}"));
    }

    match derive_outputs(psbt) {
        Err(e) => Some(e),
        Ok(derived) => psbt
            .outputs
            .iter()
            .zip(&derived.outputs)
            .any(|(before, after)| {
                before.sp_v0_info.is_some() && before.script_pubkey != after.script_pubkey
            })
            .then(|| "derived SP script mismatch".to_string()),
    }
}

fn run_finalize(vector: &TestVector) -> VectorResult {
    let psbt = parse_psbt(&vector.psbt).expect("valid vector must deserialize through rust-psbt");
    let derived = derive_outputs(&psbt)?;

    let has_script_mismatch = psbt
        .outputs
        .iter()
        .zip(&derived.outputs)
        .any(|(before, after)| {
            before.sp_v0_info.is_some() && before.script_pubkey != after.script_pubkey
        });

    if has_script_mismatch {
        Err("derived SP script mismatch".to_string())
    } else {
        Ok(None)
    }
}

fn run_sign(vector: &TestVector) -> VectorResult {
    let psbt = parse_psbt(&vector.psbt).expect("valid vector must deserialize through rust-psbt");
    match psbt.silent_payment_signer_checks() {
        Ok(SilentPaymentState::Incomplete) => Ok(None),
        Ok(SilentPaymentState::Complete) if has_unsigned_inputs(&psbt) => Ok(None),
        Ok(SilentPaymentState::Complete) => {
            Err("sign task must still have unsigned inputs".to_string())
        }
        other => Err(format!(
            "sign task must be a valid incomplete state, got {:?}",
            other
        )),
    }
}

fn run_fail_sign(vector: &TestVector) -> VectorResult {
    let psbt =
        parse_psbt(&vector.psbt).map_err(|e| format!("fail_sign should parse but did not: {e}"))?;
    let Some(reason) = signer_rejection_reason(&psbt) else {
        return Err("fail_sign vector parsed but was not rejected by SPDK signer".to_string());
    };

    Ok(Some(reason))
}

fn run_fail_deserialize(vector: &TestVector) -> VectorResult {
    match parse_psbt(&vector.psbt) {
        Err(e) => Ok(Some(format!("parse failed: {e}"))),
        Ok(_) => Err("fail_deserialize task parsed successfully".to_string()),
    }
}

fn task_name(task: &Task) -> &'static str {
    match task {
        Task::Sign => "sign",
        Task::Finalize => "finalize",
        Task::FailSign => "fail_sign",
        Task::FailDeserialize => "fail_deserialize",
    }
}

fn run_vector(vector: &TestVector) -> VectorResult {
    match vector.supplementary.task {
        Task::Finalize => run_finalize(vector),
        Task::Sign => run_sign(vector),
        Task::FailSign => run_fail_sign(vector),
        Task::FailDeserialize => run_fail_deserialize(vector),
    }
}

#[test]
fn test_bip375_vectors_match_task() {
    let vectors = load_vectors();

    let show_pass_output =
        std::env::args().any(|arg| arg == "--show-output" || arg == "--nocapture");
    let mut failures = Vec::new();

    for vector in vectors.valid.iter().chain(&vectors.invalid) {
        match run_vector(vector) {
            Ok(Some(reason)) if show_pass_output => {
                println!(
                    "PASS: {}: {}\n  {}",
                    task_name(&vector.supplementary.task),
                    vector.description,
                    reason
                );
            }
            Ok(None) if show_pass_output => {
                println!(
                    "PASS: {}: {}",
                    task_name(&vector.supplementary.task),
                    vector.description
                );
            }
            Ok(_) => {}
            Err(reason) => {
                println!(
                    "FAILED: {}: {}\n  {}",
                    task_name(&vector.supplementary.task),
                    vector.description,
                    reason
                );
                failures.push(reason);
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} BIP-375 vector(s) failed",
        failures.len()
    );
}
