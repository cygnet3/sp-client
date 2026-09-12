//! PSBT Signer Role
//!
//! This module extends the upstream [`psbt_v2::psbt::Signer`] with the two pieces of
//! the BIP-375 signer role it does not implement:
//!
//! - **ECDH share generation** ([`SpSignerExt::add_ecdh_shares`]): global shares for a
//!   single signer owning every eligible input, per-input partial shares otherwise,
//!   each with a BIP-374 DLEQ proof.
//! - **SP output script derivation** ([`SpSignerExt::derive_sp_output_scripts`]): the
//!   BIP-352 derivation that upstream's `commit_silent_payment_outputs` explicitly
//!   leaves to the caller.
//!
//! Signing itself is *not* re-implemented here: use upstream `Signer::sign` (ECDSA),
//! `Signer::sign_taproot_key_spend_inputs` and `Signer::sign_silent_payment_inputs`.

use std::collections::HashMap;
use std::fmt;

use bitcoin::key::TweakedPublicKey;
use bitcoin::{CompressedPublicKey, ScriptBuf, XOnlyPublicKey};
use psbt_v2::psbt::{GetKey, KeyRequest, Psbt, Signer as UpstreamSigner};
use psbt_v2::{
    CommitSilentPaymentOutputsError, DetermineLockTimeError, FundingUtxoError, Input,
    InvalidKeyError, SpV0Info,
};
use rand::{CryptoRng, RngCore};
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification};
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::receiving::is_eligible;
use silentpayments::utils::sending::{
    GlobalSenderEcdhShare, NormalizedSecretKey, PartialSenderEcdhShare,
};
use silentpayments::utils::{OutPoint as SpOutPoint, NUMS_H};
use silentpayments::{
    NonEmptyArray, SilentPaymentKeyMaterial, SpVersion, TransactionInputs, TransactionSharedSecret,
};

#[derive(Debug)]
pub enum SpSignerError {
    /// Funding UTXO missing or inconsistent for an input.
    FundingUtxo(FundingUtxoError),
    /// Malformed `sp_v0_info` blob on an output.
    InvalidSpV0Info(InvalidKeyError),
    /// An input is BIP-352-eligible but its pubkey cannot be named from the PSBT
    /// (e.g. P2WPKH without a matching `bip32_derivations` entry). The receiver
    /// will learn it from the finalized witness, so deriving without it would
    /// commit to the wrong input set.
    MissingInputPubkey { vin: usize },
    /// No ECDH share for this scan key on the given input.
    MissingShare {
        scan_key: CompressedPublicKey,
        vin: usize,
    },
    /// A share without its DLEQ proof (`vin: None` = global share).
    MissingDleqProof {
        scan_key: CompressedPublicKey,
        vin: Option<usize>,
    },
    /// `sp_tweak` is not a valid secp256k1 scalar.
    InvalidSpTweak { vin: usize },
    /// Structurally malformed input (e.g. `sp_tweak` set on a non-P2TR input).
    MalformedInput { vin: usize, detail: &'static str },
    /// [`ShareMode::Global`]: an eligible input's key could not be resolved from the
    /// provided [`GetKey`], so the global share cannot cover every input.
    KeyResolution { vin: usize },
    /// The [`GetKey`] backend errored during a lookup.
    GetKey { vin: usize, error: String },
    /// [`ShareMode::Partial`]: none of the inputs are owned by the provided keys.
    NoOwnedInputs,
    /// Shares for the requested mode already exist; refusing to overwrite.
    SharesAlreadyPresent,
    /// Global and per-input partial shares must not coexist when *adding*
    /// shares (derivation tolerates the mix per BIP-375: the global share
    /// takes precedence).
    MixedShareState,
    /// A signature is already present; BIP-375 requires shares before signatures.
    AlreadySigned { vin: usize },
    /// silentpayments crypto layer failure.
    SilentPayments(silentpayments::Error),
    /// secp256k1 failure.
    Secp256k1(secp256k1::Error),
    /// Upstream lock-time determination failed when constructing the commit signer.
    DetermineLockTime(DetermineLockTimeError),
    /// Upstream `commit_silent_payment_outputs` rejected the derived scripts.
    CommitOutputs(CommitSilentPaymentOutputsError),
}

impl fmt::Display for SpSignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SpSignerError as E;
        match self {
            E::FundingUtxo(e) => write!(f, "funding utxo error: {e}"),
            E::InvalidSpV0Info(e) => write!(f, "invalid sp_v0_info: {e}"),
            E::MissingInputPubkey { vin } => write!(
                f,
                "input {vin}: BIP-352 eligible but its pubkey cannot be named from the PSBT"
            ),
            E::MissingShare { scan_key, vin } => {
                write!(f, "no ECDH share for scan key {scan_key} on input {vin}")
            }
            E::MissingDleqProof {
                scan_key,
                vin: Some(vin),
            } => write!(f, "no DLEQ proof for scan key {scan_key} on input {vin}"),
            E::MissingDleqProof {
                scan_key,
                vin: None,
            } => write!(
                f,
                "no DLEQ proof for the global share of scan key {scan_key}"
            ),
            E::InvalidSpTweak { vin } => write!(f, "input {vin}: sp_tweak is not a valid scalar"),
            E::MalformedInput { vin, detail } => write!(f, "input {vin}: malformed: {detail}"),
            E::KeyResolution { vin } => write!(
                f,
                "single signer cannot resolve the spending key for eligible input {vin}"
            ),
            E::GetKey { vin, error } => write!(f, "input {vin}: GetKey backend error: {error}"),
            E::NoOwnedInputs => f.write_str("no inputs owned by the provided keys"),
            E::SharesAlreadyPresent => {
                f.write_str("ECDH shares already present, refusing to overwrite")
            }
            E::MixedShareState => f.write_str("global and per-input ECDH shares must not coexist"),
            E::AlreadySigned { vin } => write!(
                f,
                "input {vin} already carries a signature; shares must be added before signing"
            ),
            E::SilentPayments(e) => write!(f, "silent payments error: {e}"),
            E::Secp256k1(e) => write!(f, "secp256k1 error: {e}"),
            E::DetermineLockTime(e) => write!(f, "cannot determine lock time: {e}"),
            E::CommitOutputs(e) => write!(f, "failed to commit silent payment outputs: {e}"),
        }
    }
}

impl std::error::Error for SpSignerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SpSignerError as E;
        match self {
            E::FundingUtxo(e) => Some(e),
            E::InvalidSpV0Info(e) => Some(e),
            E::SilentPayments(e) => Some(e),
            E::Secp256k1(e) => Some(e),
            _ => None,
        }
    }
}

impl From<FundingUtxoError> for SpSignerError {
    fn from(value: FundingUtxoError) -> Self {
        Self::FundingUtxo(value)
    }
}

impl From<InvalidKeyError> for SpSignerError {
    fn from(value: InvalidKeyError) -> Self {
        Self::InvalidSpV0Info(value)
    }
}

impl From<silentpayments::Error> for SpSignerError {
    fn from(value: silentpayments::Error) -> Self {
        Self::SilentPayments(value)
    }
}

impl From<secp256k1::Error> for SpSignerError {
    fn from(value: secp256k1::Error) -> Self {
        Self::Secp256k1(value)
    }
}

impl From<DetermineLockTimeError> for SpSignerError {
    fn from(value: DetermineLockTimeError) -> Self {
        Self::DetermineLockTime(value)
    }
}

impl From<CommitSilentPaymentOutputsError> for SpSignerError {
    fn from(value: CommitSilentPaymentOutputsError) -> Self {
        Self::CommitOutputs(value)
    }
}

/// Who am I in this transaction? Explicit, not auto-detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    /// I own every eligible input: write global shares (BIP-375 single-signer path).
    /// Errors loudly if any eligible input's key can't be resolved.
    Global,
    /// I own some inputs: write per-input partial shares for owned inputs only,
    /// skip the rest.
    Partial,
}

pub trait SpSignerExt {
    /// BIP-375 signer, phase 1: add ECDH shares + DLEQ proofs for every scan key
    /// among the SP outputs. Returns the scan keys that received shares so the
    /// caller can verify coverage before forwarding the PSBT.
    ///
    /// No-op (returning an empty vec) when the PSBT has no SP outputs.
    ///
    /// # Errors
    ///
    /// - [`SpSignerError::AlreadySigned`] if any input already carries a signature
    ///   (BIP-375 requires shares before signatures).
    /// - [`SpSignerError::SharesAlreadyPresent`] / [`SpSignerError::MixedShareState`]
    ///   if shares already exist.
    /// - [`SpSignerError::KeyResolution`] ([`ShareMode::Global`]) if an eligible
    ///   input's key cannot be resolved.
    /// - [`SpSignerError::NoOwnedInputs`] ([`ShareMode::Partial`]) if no input is
    ///   owned by `keys`.
    fn add_ecdh_shares<C, R, K>(
        &mut self,
        secp: &Secp256k1<C>,
        rng: &mut R,
        keys: &K,
        mode: ShareMode,
    ) -> Result<Vec<CompressedPublicKey>, SpSignerError>
    where
        C: Signing + Verification,
        R: RngCore + CryptoRng,
        K: GetKey;

    /// BIP-352, phase 2: derive output scripts from whatever shares are present
    /// (global or aggregated partial). Pure — no mutation. Output-index keyed so
    /// it feeds upstream `commit_silent_payment_outputs` directly.
    ///
    /// When a scan key has both a global share and per-input shares, the global
    /// share takes precedence (BIP-375 "Computing the Output Scripts"); if it
    /// fails verification, complete per-input coverage is tried as a fallback
    /// (sound: a verified partial proof binds its share to the input's key).
    fn derive_sp_output_scripts<C>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<(usize, ScriptBuf)>, SpSignerError>
    where
        C: Signing + Verification;

    /// Single-signer convenience: derive + commit in one step. The commit is
    /// upstream's `commit_silent_payment_outputs`, which runs the BIP-375 signer
    /// checks and clears the modifiable flags. `self` is left untouched on error.
    fn commit_sp_outputs<C>(&mut self, secp: &Secp256k1<C>) -> Result<(), SpSignerError>
    where
        C: Signing + Verification;
}

impl SpSignerExt for Psbt {
    fn add_ecdh_shares<C, R, K>(
        &mut self,
        secp: &Secp256k1<C>,
        rng: &mut R,
        keys: &K,
        mode: ShareMode,
    ) -> Result<Vec<CompressedPublicKey>, SpSignerError>
    where
        C: Signing + Verification,
        R: RngCore + CryptoRng,
        K: GetKey,
    {
        let scan_keys = collect_scan_keys(&collect_sp_v0_keys(self))?;
        if scan_keys.is_empty() {
            // No SP outputs: nothing to do.
            return Ok(Vec::new());
        }

        // BIP-375: shares are added before any signature. A signature present at
        // this point means the output scripts are already committed and adding
        // shares can only produce an inconsistent PSBT.
        for (vin, input) in self.inputs.iter().enumerate() {
            if !input.partial_sigs.is_empty() || input.tap_key_sig.is_some() {
                return Err(SpSignerError::AlreadySigned { vin });
            }
        }

        match mode {
            ShareMode::Global => {
                if !self.global.sp_ecdh_shares.is_empty() {
                    return Err(SpSignerError::SharesAlreadyPresent);
                }
                if self.inputs.iter().any(|i| !i.sp_ecdh_shares.is_empty()) {
                    return Err(SpSignerError::MixedShareState);
                }

                // A single signer owns every input that contributes to the ECDH,
                // so resolving each of them is mandatory. Inputs excluded by
                // convention (non-eligible scripts, NUMS_H internal key) are
                // skipped, mirroring what the receiver will do.
                let mut summed_keys: Vec<NormalizedSecretKey> =
                    Vec::with_capacity(self.inputs.len());
                for (vin, input) in self.inputs.iter().enumerate() {
                    if !is_ecdh_contributing(input)? {
                        continue;
                    }
                    let input_key = resolve_owned_eligible_key(secp, input, vin, keys)?
                        .ok_or(SpSignerError::KeyResolution { vin })?;
                    let is_taproot = input.funding_utxo()?.script_pubkey.is_p2tr();
                    summed_keys.push(NormalizedSecretKey::new(secp, input_key, is_taproot));
                }

                for scan_key in &scan_keys {
                    let mut aux_rand = [0u8; 32];
                    rng.fill_bytes(&mut aux_rand);
                    let global_share = GlobalSenderEcdhShare::new_from_summed_keys(
                        secp,
                        scan_key.0,
                        NonEmptyArray::new(&summed_keys)?,
                        &aux_rand,
                    )?;
                    self.global.sp_ecdh_shares.insert(
                        *scan_key,
                        CompressedPublicKey(*global_share.as_ecdh_shared_secret()),
                    );
                    self.global
                        .sp_dleq_proofs
                        .insert(*scan_key, to_psbt_dleq(*global_share.dleq_proof()));
                }
            }
            ShareMode::Partial => {
                if !self.global.sp_ecdh_shares.is_empty() {
                    return Err(SpSignerError::MixedShareState);
                }

                // First pass: resolve every owned input and validate, so the PSBT
                // is never left half-written when a later input errors.
                let mut owned: Vec<(usize, NormalizedSecretKey)> = Vec::new();
                for (vin, input) in self.inputs.iter().enumerate() {
                    // Only contribute shares for inputs this signer actually owns.
                    let Some(input_key) = resolve_owned_eligible_key(secp, input, vin, keys)?
                    else {
                        continue;
                    };
                    if scan_keys
                        .iter()
                        .any(|k| input.sp_ecdh_shares.contains_key(k))
                    {
                        return Err(SpSignerError::SharesAlreadyPresent);
                    }
                    let is_taproot = input.funding_utxo()?.script_pubkey.is_p2tr();
                    owned.push((vin, NormalizedSecretKey::new(secp, input_key, is_taproot)));
                }
                if owned.is_empty() {
                    return Err(SpSignerError::NoOwnedInputs);
                }

                // Second pass: write the shares.
                for (vin, normalized) in &owned {
                    let input = &mut self.inputs[*vin];
                    for scan_key in &scan_keys {
                        let mut aux_rand = [0u8; 32];
                        rng.fill_bytes(&mut aux_rand);
                        let partial = PartialSenderEcdhShare::new(
                            secp, scan_key.0, *vin, normalized, &aux_rand,
                        )?;
                        input.sp_ecdh_shares.insert(
                            *scan_key,
                            CompressedPublicKey(*partial.as_ecdh_shared_secret()),
                        );
                        input
                            .sp_dleq_proofs
                            .insert(*scan_key, to_psbt_dleq(*partial.dleq_proof()));
                    }
                }
            }
        }

        Ok(scan_keys)
    }

    fn derive_sp_output_scripts<C>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<(usize, ScriptBuf)>, SpSignerError>
    where
        C: Signing + Verification,
    {
        // Recipient key material per SP output. `generate_recipient_pubkeys` assigns
        // the BIP-352 n-counter within each scan-key group in the order entries are
        // given, and the reference vectors expect that order to be the outputs sorted
        // by `sp_v0_info` (ties broken by output index) — not raw output order. This
        // matters when one scan key is paid with different labels.
        let sp_outputs = collect_sp_v0_keys(self);
        if sp_outputs.is_empty() {
            return Ok(Vec::new());
        }

        let sorted_materials: Vec<SilentPaymentKeyMaterial> = sp_outputs
            .iter()
            .map(|(_, sp_info)| sp_info_to_key_material(sp_info))
            .collect::<Result<_, _>>()?;

        let scan_keys = collect_scan_keys(&sp_outputs)?;

        // The BIP-352 input set, exactly as the receiver rebuilds it.
        let mut transaction_inputs = TransactionInputs::with_capacity(self.global.input_count);
        for (vin, input) in self.inputs.iter().enumerate() {
            let outpoint = SpOutPoint::from_txid_and_vout(
                input.previous_txid.to_string(),
                input.spent_output_index,
            )?;
            let spk = input.funding_utxo()?.script_pubkey.to_bytes();
            let pubkey = extract_eligible_input_pubkey(input)?;
            if pubkey.is_none() && is_ecdh_contributing(input)? {
                return Err(SpSignerError::MissingInputPubkey { vin });
            }
            transaction_inputs.push(outpoint, spk, pubkey);
        }
        let eligible_vins = transaction_inputs.eligible_vins();

        // Aggregate of every eligible input's partial share for one scan key.
        // Primary source when no global share exists, fallback when the global
        // share fails verification (see below).
        let partials_secret =
            |ck: CompressedPublicKey| -> Result<TransactionSharedSecret, SpSignerError> {
                // Every eligible input must provide a partial share with its proof.
                let mut partials = Vec::with_capacity(eligible_vins.len());
                for &vin in &eligible_vins {
                    let input = &self.inputs[vin];
                    let share = input
                        .sp_ecdh_shares
                        .get(&ck)
                        .ok_or(SpSignerError::MissingShare { scan_key: ck, vin })?;
                    let proof =
                        input
                            .sp_dleq_proofs
                            .get(&ck)
                            .ok_or(SpSignerError::MissingDleqProof {
                                scan_key: ck,
                                vin: Some(vin),
                            })?;
                    partials.push(PartialSenderEcdhShare::new_unchecked(
                        ck.0,
                        vin,
                        share.0,
                        to_rust_dleq(*proof),
                    ));
                }
                Ok(TransactionSharedSecret::new_from_partial_shares(
                    secp,
                    ck.0,
                    NonEmptyArray::new(&partials)?,
                    &transaction_inputs,
                )?)
            };

        // One transaction shared secret per scan key. DLEQ proofs are verified
        // inside the `TransactionSharedSecret` constructors.
        let mut shared_secrets: HashMap<PublicKey, TransactionSharedSecret> =
            HashMap::with_capacity(scan_keys.len());
        for ck in scan_keys {
            // A global share takes precedence (BIP-375 "Computing the Output
            // Scripts": use PSBT_GLOBAL_SP_ECDH_SHARE "if available"). Combiners
            // can legitimately produce PSBTs that also carry per-input shares for
            // the same scan key — the official vectors treat that state as valid
            // — so coexisting partials never replace a *verifiable* global share.
            // We never *produce* the overlap ourselves: `add_ecdh_shares` rejects
            // it.
            //
            // Fallback: when the global share fails verification, complete partial
            // coverage is tried before giving up. This is sound because a verified
            // partial DLEQ proof binds its share to the input's prevout pubkey,
            // so fully verified partials determine the one correct secret — the
            // fallback can only recover that value or fail, never commit to a
            // wrong one. If the fallback fails too, the original global error is
            // reported. A *missing* global proof does not fall back: BIP-375
            // lists it as an invalid state.
            let scan_key = ck.0;
            let shared_secret = if let Some(share) = self.global.sp_ecdh_shares.get(&ck) {
                let proof =
                    self.global
                        .sp_dleq_proofs
                        .get(&ck)
                        .ok_or(SpSignerError::MissingDleqProof {
                            scan_key: ck,
                            vin: None,
                        })?;
                let global =
                    GlobalSenderEcdhShare::new_unchecked(scan_key, share.0, to_rust_dleq(*proof));
                TransactionSharedSecret::new_from_global_share(secp, &global, &transaction_inputs)
                    .or_else(|global_err| partials_secret(ck).map_err(|_| global_err))?
            } else {
                partials_secret(ck)?
            };
            shared_secrets.insert(scan_key, shared_secret);
        }

        let mut derived = generate_recipient_pubkeys(secp, sorted_materials, &shared_secrets)?;

        // Assign back in output-index order: within one key material the sorted
        // order coincides with index order, so popping per material is exact.
        let mut scripts = Vec::with_capacity(sp_outputs.len());
        for (index, sp_info) in sp_outputs {
            let key_material = sp_info_to_key_material(&sp_info)?;
            let keys = derived
                .get_mut(&key_material)
                .expect("every submitted recipient is derived");
            let xonly = keys
                .first()
                .copied()
                .expect("one derived key per submitted recipient");
            keys.remove(0);
            scripts.push((
                index,
                ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(xonly)),
            ));
        }
        Ok(scripts)
    }

    fn commit_sp_outputs<C>(&mut self, secp: &Secp256k1<C>) -> Result<(), SpSignerError>
    where
        C: Signing + Verification,
    {
        let scripts = self.derive_sp_output_scripts(secp)?;
        // Upstream commit: refuses script mismatches, clears the modifiable flags
        // (without clobbering SIGHASH_SINGLE) and runs the BIP-375 signer checks.
        // Operate on a clone so `self` stays untouched on error.
        let mut signer = UpstreamSigner::new(self.clone())?;
        signer.commit_silent_payment_outputs(scripts)?;
        *self = signer.psbt();
        Ok(())
    }
}

/// Distinct scan keys among the SP outputs. It must be called with the output of `collect_sp_v0_keys`
/// to garantee it is sorted. We still sort the keys before deduping to be sure.
fn collect_scan_keys(
    sp_v0_info: &[(usize, SpV0Info)],
) -> Result<Vec<CompressedPublicKey>, InvalidKeyError> {
    let mut res = sp_v0_info
        .iter()
        .map(|(_, x)| x.scan_key())
        .collect::<Result<Vec<_>, _>>()?;
    res.sort_unstable();
    res.dedup();
    Ok(res)
}

/// Build the v0 key material from the 66-byte `sp_v0_info` blob (scan key ‖ spend key,
/// both compressed).
fn sp_info_to_key_material(
    sp_info: &SpV0Info,
) -> Result<SilentPaymentKeyMaterial, InvalidKeyError> {
    Ok(SilentPaymentKeyMaterial::new(
        SpVersion::ZERO,
        sp_info.scan_key()?.0,
        sp_info.spend_key()?.0,
    ))
}

/// Collects all the sp v0 keys in psbt's outputs with their output index, already sorted according to BIP375
fn collect_sp_v0_keys(psbt: &Psbt) -> Vec<(usize, SpV0Info)> {
    let mut res: Vec<_> = psbt
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(i, o)| {
            if let Some(sp_info) = o.sp_v0_info {
                Some((i, sp_info))
            } else {
                None
            }
        })
        .collect();
    res.sort_unstable_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    res
}

/// Extract the BIP-352 input public key from PSBT fields populated by the Updater.
///
/// Returns `Some(pubkey)` for each eligible script type:
/// - **P2TR**: reads the output key from the funding scriptPubKey, promoted to even parity
///   (BIP-352 §3). This also covers SP inputs (`sp_tweak` set): per BIP-376 the
///   `sp_spend_bip32_derivations` map key is the *untweaked* spend key `B_spend`, used only
///   for signer key lookup — the key used for ECDH is the output key itself, which is
///   `B_spend + tweak·G` by construction. Reading it from the prevout instead of an
///   updater-declared field is what makes a wrong or malicious `sp_tweak` fail closed at
///   key-resolution time.
/// - **P2TR without `sp_tweak`**: a NUMS_H `tap_internal_key` means no key path, so the
///   input is skipped (BIP-352 §3). SP outputs always have a key path, so the exception
///   does not apply to them.
/// - **P2WPKH / P2PKH**: reads from `bip32_derivations`.
/// - **P2SH-P2WPKH**: checks that `redeem_script` is P2WPKH, then reads from `bip32_derivations`.
///
/// Returns `Ok(None)` when the input does not contribute to the ECDH, when the required
/// PSBT fields have not been populated by the Updater yet, or when no `bip32_derivations`
/// entry verifies against the funding script. Callers that require a pubkey for every
/// contributing input (share generation in [`ShareMode::Global`], output derivation)
/// must turn that `None` into an error themselves.
pub fn extract_eligible_input_pubkey(input: &Input) -> Result<Option<PublicKey>, SpSignerError> {
    if !is_ecdh_contributing(input)? {
        return Ok(None);
    }

    let funding_utxo = input.funding_utxo()?;
    let spk = &funding_utxo.script_pubkey;

    if spk.is_p2tr() {
        // BIP-352 §3: use the taproot **output key** (from the scriptPubKey), not the
        // internal key. The sender signs with the tweaked private key and the receiver
        // reads the same key from the scriptPubKey.
        let output_xonly = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..])?;
        Ok(Some(output_xonly.public_key(Parity::Even)))
    } else if spk.is_p2sh() {
        let Some(redeem_script) = input.redeem_script.as_ref() else {
            return Ok(None);
        };
        Ok(input
            .bip32_derivations
            .keys()
            .find(|pk| pubkey_matches_funding_script(pk, spk, Some(redeem_script)))
            .map(|pk| pk.inner))
    } else {
        // P2WPKH / P2PKH: the pubkey must verify against the funding script —
        // otherwise the derived secret commits to a key the receiver never sees.
        Ok(input
            .bip32_derivations
            .keys()
            .find(|pk| pubkey_matches_funding_script(pk, spk, None))
            .map(|pk| pk.inner))
    }
}

/// Whether BIP-352 expects this input to contribute to the ECDH aggregation: an
/// eligible script, excluding the NUMS_H script-path-only exception (§3). The
/// exception does not apply to SP inputs (`sp_tweak` set): they always have a
/// key path.
///
/// P2SH contributes only as P2SH-P2WPKH, which is only knowable from the redeem
/// script — a bare P2SH input (or one the Updater has not populated yet) is
/// treated as non-contributing.
fn is_ecdh_contributing(input: &Input) -> Result<bool, SpSignerError> {
    let spk = &input.funding_utxo()?.script_pubkey;
    if !is_eligible(spk.as_bytes()) {
        return Ok(false);
    }
    if spk.is_p2sh() {
        return Ok(input.redeem_script.as_ref().is_some_and(|r| r.is_p2wpkh()));
    }
    if spk.is_p2tr() && input.sp_tweak.is_none() {
        if let Some(internal_key) = input.tap_internal_key {
            if internal_key.serialize() == NUMS_H {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Resolve the private key for an eligible input owned by `keys`.
///
/// The lookup strategy mirrors upstream signing so that the set of inputs we
/// contribute ECDH shares for is exactly the set of inputs we can later sign:
///
/// - **SP P2TR** (`sp_tweak` set): requests the *untweaked* spend key from
///   `sp_spend_bip32_derivations` (BIP-32 first, then pubkey), falling back to
///   candidate spend keys recovered from the output key when the map is empty —
///   the same fallback rust-psbt's `sign_silent_payment_inputs` uses. The tweak is
///   applied after lookup and verified against the prevout's output key, so a wrong
///   or malicious `sp_tweak` fails closed here.
/// - **Plain P2TR**: requests the even-lifted output key by pubkey, like upstream's
///   `sign_taproot_key_spend_inputs`.
/// - **P2WPKH / P2PKH / P2SH-P2WPKH**: iterates `bip32_derivations`, but only after
///   verifying the pubkey against the funding script — a wrong pubkey here produces
///   a share the receiver can never match.
///
/// Returns `Ok(None)` for inputs that are not eligible or not owned by `keys`.
fn resolve_owned_eligible_key<C, K>(
    secp: &Secp256k1<C>,
    input: &Input,
    vin: usize,
    keys: &K,
) -> Result<Option<SecretKey>, SpSignerError>
where
    C: Signing + Verification,
    K: GetKey,
{
    let funding_utxo = input.funding_utxo()?;
    let spk = &funding_utxo.script_pubkey;

    if !is_eligible(spk.as_bytes()) {
        return Ok(None);
    }

    let get = |req: KeyRequest| -> Result<Option<SecretKey>, SpSignerError> {
        keys.get_key(req, secp)
            .map(|opt| opt.map(|sk| sk.inner))
            .map_err(|e| SpSignerError::GetKey {
                vin,
                error: format!("{e:?}"),
            })
    };

    if let Some(tweak_bytes) = input.sp_tweak {
        if !spk.is_p2tr() {
            return Err(SpSignerError::MalformedInput {
                vin,
                detail: "sp_tweak set on a non-P2TR input",
            });
        }
        let tweak = Scalar::from_be_bytes(tweak_bytes)
            .map_err(|_| SpSignerError::InvalidSpTweak { vin })?;
        let output_xonly = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34])?;

        // BIP-376: the derivation map is keyed by the *untweaked* spend key.
        for (spend_key, key_source) in &input.sp_spend_bip32_derivations {
            let sk = match get(KeyRequest::Bip32(key_source.clone()))? {
                Some(sk) => Some(sk),
                None => get(KeyRequest::Pubkey(bitcoin::PublicKey::from(*spend_key)))?,
            };
            if let Some(tweaked) =
                sk.and_then(|sk| apply_tweak_and_verify(secp, sk, tweak, output_xonly))
            {
                return Ok(Some(tweaked));
            }
        }

        // Fallback for an unpopulated map: recover candidate spend keys from the
        // output key, mirroring rust-psbt's signing fallback.
        if input.sp_spend_bip32_derivations.is_empty() {
            for candidate in spend_key_candidates(output_xonly, tweak, secp) {
                if let Some(tweaked) = get(KeyRequest::Pubkey(candidate))?
                    .and_then(|sk| apply_tweak_and_verify(secp, sk, tweak, output_xonly))
                {
                    return Ok(Some(tweaked));
                }
            }
        }
        return Ok(None);
    }

    if spk.is_p2tr() {
        // Exception (BIP-352 §3): a NUMS_H internal key means no key path, so there
        // is no private key to contribute — skip this input.
        if let Some(internal_key) = input.tap_internal_key {
            if internal_key.serialize() == NUMS_H {
                return Ok(None);
            }
        }
        let output_xonly = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34])?;
        let request = bitcoin::PublicKey::new(output_xonly.public_key(Parity::Even));
        return Ok(get(KeyRequest::Pubkey(request))?
            .filter(|sk| sk.x_only_public_key(secp).0 == output_xonly));
    }

    // P2WPKH / P2PKH / P2SH-P2WPKH.
    for (pk, key_source) in &input.bip32_derivations {
        if !pubkey_matches_funding_script(pk, spk, input.redeem_script.as_ref()) {
            continue;
        }
        let sk = match get(KeyRequest::Bip32(key_source.clone()))? {
            Some(sk) => Some(sk),
            None => get(KeyRequest::Pubkey(*pk))?,
        };
        if let Some(sk) = sk.filter(|sk| sk.public_key(secp) == pk.inner) {
            return Ok(Some(sk));
        }
    }
    Ok(None)
}

/// Apply `sp_tweak` to a candidate spend key and check it produces the prevout's
/// output key (x-only comparison). This is the fail-closed BIP-376 tweak check.
fn apply_tweak_and_verify<C: Signing>(
    secp: &Secp256k1<C>,
    spend_sk: SecretKey,
    tweak: Scalar,
    output_key: XOnlyPublicKey,
) -> Option<SecretKey> {
    let tweaked = spend_sk.add_tweak(&tweak).ok()?;
    (tweaked.x_only_public_key(secp).0 == output_key).then_some(tweaked)
}

/// Candidate untweaked spend keys for an SP output key: `output_key - tweak·G`
/// under both parities. Mirrors rust-psbt's private `spend_key_candidates`.
fn spend_key_candidates<C: Signing + Verification>(
    output_key: XOnlyPublicKey,
    tweak: Scalar,
    secp: &Secp256k1<C>,
) -> Vec<bitcoin::PublicKey> {
    if tweak == Scalar::ZERO {
        return [Parity::Even, Parity::Odd]
            .into_iter()
            .map(|p| bitcoin::PublicKey::new(output_key.public_key(p)))
            .collect();
    }
    let Ok(tweak_sk) = SecretKey::from_slice(&tweak.to_be_bytes()) else {
        return Vec::new();
    };
    let negated_tweak_key = tweak_sk.public_key(secp).negate(secp);
    [Parity::Even, Parity::Odd]
        .into_iter()
        .filter_map(|p| output_key.public_key(p).combine(&negated_tweak_key).ok())
        .map(bitcoin::PublicKey::new)
        .collect()
}

/// Check that `pubkey` is the key committed by the funding scriptPubKey.
fn pubkey_matches_funding_script(
    pubkey: &bitcoin::PublicKey,
    spk: &ScriptBuf,
    redeem_script: Option<&ScriptBuf>,
) -> bool {
    if spk.is_p2wpkh() {
        return pubkey
            .wpubkey_hash()
            .is_ok_and(|h| ScriptBuf::new_p2wpkh(&h) == *spk);
    }
    if spk.is_p2pkh() {
        return ScriptBuf::new_p2pkh(&pubkey.pubkey_hash()) == *spk;
    }
    if spk.is_p2sh() {
        let Some(redeem) = redeem_script else {
            return false;
        };
        return redeem.is_p2wpkh()
            && ScriptBuf::new_p2sh(&redeem.script_hash()) == *spk
            && pubkey
                .wpubkey_hash()
                .is_ok_and(|h| ScriptBuf::new_p2wpkh(&h) == *redeem);
    }
    false
}

/// Convert a `rust_dleq` proof into the PSBT-serializable proof type.
///
/// Both are newtypes over the same 64-byte encoding.
fn to_psbt_dleq(p: rust_dleq::DleqProof) -> psbt_v2::dleq::DleqProof {
    psbt_v2::dleq::DleqProof(p.0)
}

/// Convert a PSBT-field DLEQ proof into the rust-dleq type used by `silentpayments`.
fn to_rust_dleq(p: psbt_v2::dleq::DleqProof) -> rust_dleq::DleqProof {
    rust_dleq::DleqProof(p.0)
}
