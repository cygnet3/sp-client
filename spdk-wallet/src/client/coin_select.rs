use std::collections::HashSet;

use anyhow::{Error, Result};
use bdk_coin_select::float::Ordf32;
use bdk_coin_select::metrics::{Changeless, LowestFee};
use bdk_coin_select::{
    BnbMetric, Candidate, ChangePolicy, CoinSelector, Drain, DrainWeights, FeeRate,
    TR_DUST_RELAY_MIN_VALUE, TR_KEYSPEND_SATISFACTION_WEIGHT, TR_KEYSPEND_TXIN_WEIGHT,
    TR_SPK_WEIGHT, TXOUT_BASE_WEIGHT, Target, TargetFee, TargetOutputs,
};
use bitcoin::script::PushBytesBuf;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use spdk_core::constants::DATA_CARRIER_SIZE;

use crate::client::{Recipient, RecipientAddress};

/// Upper bound on branch-and-bound iterations (see `bdk_coin_select` README).
const BNB_MAX_ROUNDS: usize = 100_000;

/// Compact-size item count + <sig> + <pubkey> in the witness (weight units).
const P2WPKH_SATISFACTION_WEIGHT: u64 = 1 + (1 + 72) + (1 + 33);
/// Same stack items in the scriptSig, scaled by WITNESS_SCALE_FACTOR.
const P2PKH_SATISFACTION_WEIGHT: u64 = (1 + 72 + 1 + 33) * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Changeless,
    LowestFee,
    FeeRateCap, // Only accepts selections whose implied fee rate stays within the bound, then minimize fees
    Greedy,     // Fallback
    Drain,      // for the drain transaction case
}

fn candidate_from_txout(txout: &TxOut) -> Result<Candidate> {
    let spk = &txout.script_pubkey;
    let (satisfaction_weight, is_segwit) = if spk.is_p2tr() {
        // Keyspend only. Script-path satisfaction is not visible on the TxOut.
        (TR_KEYSPEND_SATISFACTION_WEIGHT, true)
    } else if spk.is_p2wpkh() {
        (P2WPKH_SATISFACTION_WEIGHT, true)
    } else if spk.is_p2pkh() {
        (P2PKH_SATISFACTION_WEIGHT, false)
    } else {
        return Err(anyhow::Error::msg(format!(
            "unsupported input script for coin selection: {spk}"
        )));
    };
    Ok(Candidate::new(
        txout.value.to_sat(),
        satisfaction_weight,
        is_segwit,
    ))
}

fn pool_from_utxos(utxos: &[(OutPoint, TxOut)]) -> Result<(Vec<OutPoint>, Vec<Candidate>)> {
    let mut seen: HashSet<OutPoint> = HashSet::with_capacity(utxos.len());
    let mut outpoints = Vec::with_capacity(utxos.len());
    let mut candidates = Vec::with_capacity(utxos.len());
    for (outpoint, txout) in utxos {
        if !seen.insert(*outpoint) {
            return Err(Error::msg(format!("duplicate outpoint: {outpoint}")));
        }
        outpoints.push(*outpoint);
        candidates.push(candidate_from_txout(txout)?);
    }
    Ok((outpoints, candidates))
}

/// Returns the output weight in weight units for the given recipient.
///
/// For silent-payment recipients the actual script pubkey is not known yet (the key is derived in
/// [`finalize_transaction`]), but the output is always P2TR (OP_PUSHNUM_1 + 32-byte key = 34
/// bytes). We build a zero-byte placeholder script of that exact shape and call
/// [`TxOut::weight`] so the bitcoin library owns the arithmetic.
fn recipient_output_weight(recipient: &Recipient) -> u64 {
    let spk: ScriptBuf = match &recipient.address {
        // SP outputs are always P2TR; placeholder key is all-zeros.
        RecipientAddress::SpCode(_) => ScriptBuf::from_bytes(
            [0x51u8, 0x20] // OP_PUSHNUM_1, OP_PUSHBYTES_32
                .into_iter()
                .chain([0u8; 32])
                .collect(),
        ),
        RecipientAddress::LegacyAddress(addr) => addr.assume_checked_ref().script_pubkey(),
        RecipientAddress::Data(data) => {
            let data_len = data.len().min(DATA_CARRIER_SIZE);
            let mut buf = PushBytesBuf::with_capacity(data_len);
            // DATA_CARRIER_SIZE (205) is well within the PushBytes limit (520).
            buf.extend_from_slice(&data[..data_len])
                .expect("DATA_CARRIER_SIZE is within PushBytes limits");
            ScriptBuf::new_op_return(buf)
        }
    };
    TxOut {
        value: Amount::ZERO,
        script_pubkey: spk,
    }
    .weight()
    .to_wu()
}

#[derive(Debug)]
pub struct InputSelection {
    pub selected_utxos: Vec<OutPoint>,
    pub sent: Amount,
    pub n_sent_outputs: usize,
    pub change: Amount,
    pub n_change_outputs: usize,
    pub fee: Amount,
    pub actual_fee_rate: FeeRate,
    pub strategy: Strategy,
}

pub fn select_all_utxos_for_fee_rate(
    available_utxos: &[(OutPoint, TxOut)],
    recipients: &[Recipient],
    fee_rate: FeeRate,
) -> Result<InputSelection> {
    let (outpoints, candidates) = pool_from_utxos(available_utxos)?;

    let mut coin_selector = CoinSelector::new(&candidates);

    let n_outputs = recipients.len();
    let output_weight: u64 = recipients.iter().map(recipient_output_weight).sum();

    let drain_output = DrainWeights {
        output_weight,
        spend_weight: 0,
        n_outputs,
    };

    let change_policy = ChangePolicy::min_value(drain_output, TR_DUST_RELAY_MIN_VALUE);

    let target = Target {
        fee: TargetFee::from_feerate(fee_rate),
        outputs: TargetOutputs {
            value_sum: 0,
            weight_sum: 0,
            n_outputs: 0,
        },
    };

    coin_selector.select_all();

    let change = coin_selector.drain(target, change_policy);

    if change.is_none() {
        return Err(anyhow::Error::msg("No funds available"));
    }

    let fee_value = coin_selector.fee(target.outputs.value_sum, change.value);
    if fee_value < 0 {
        return Err(anyhow::Error::msg("Not enough funds available")); // Maybe if we have very little funds and environment is high fees?
    }

    let actual_fee_rate = coin_selector
        .implied_feerate(target.outputs, change)
        .ok_or_else(|| anyhow::Error::msg("cannot compute effective feerate for selection"))?;

    Ok(InputSelection {
        selected_utxos: outpoints,
        sent: Amount::from_sat(change.value),
        n_sent_outputs: n_outputs,
        change: Amount::ZERO,
        n_change_outputs: 0,
        fee: Amount::from_sat(fee_value as u64),
        actual_fee_rate,
        strategy: Strategy::Drain,
    })
}

struct SelectionContext<'a> {
    outpoints: &'a [OutPoint],
    candidates: &'a [Candidate],
    must_select: &'a HashSet<OutPoint>,
    target: Target,
    change_policy: ChangePolicy,
    fee_rate: FeeRate,
    n_change_outputs: usize,
}

fn finalize_selection(
    ctx: &SelectionContext<'_>,
    coin_selector: &CoinSelector<'_>,
    strategy: Strategy,
) -> Result<InputSelection> {
    let selected_utxos = coin_selector
        .selected_indices()
        .iter()
        .map(|i| ctx.outpoints[*i])
        .collect();

    let change = coin_selector.drain(ctx.target, ctx.change_policy);
    let change_value = if change.is_some() { change.value } else { 0 };
    let n_change_outputs = if change_value == 0 {
        0
    } else {
        ctx.n_change_outputs
    };

    let outputs_value = ctx.target.outputs.value_sum;

    let fee_value = coin_selector.fee(outputs_value, change_value);
    if fee_value < 0 {
        return Err(anyhow::Error::msg("Not enough funds available"));
    }

    let actual_fee_rate = coin_selector
        .implied_feerate(ctx.target.outputs, change)
        .ok_or_else(|| anyhow::Error::msg("cannot compute effective feerate for selection"))?;

    Ok(InputSelection {
        selected_utxos,
        sent: Amount::from_sat(outputs_value),
        n_sent_outputs: ctx.target.outputs.n_outputs,
        change: Amount::from_sat(change_value),
        n_change_outputs,
        fee: Amount::from_sat(fee_value as u64),
        actual_fee_rate,
        strategy,
    })
}

fn selector_with_mandatory_inputs<'a>(ctx: &SelectionContext<'a>) -> CoinSelector<'a> {
    // every must_select outpoint is guaranteed to be in the pool by
    // pick_utxos_for_fee_rate's precondition check
    let mut coin_selector = CoinSelector::new(ctx.candidates);
    for (index, outpoint) in ctx.outpoints.iter().enumerate() {
        if ctx.must_select.contains(outpoint) {
            coin_selector.select(index);
        }
    }
    coin_selector
}

fn try_changeless_selection(
    ctx: &SelectionContext<'_>,
    mut coin_selector: CoinSelector<'_>,
) -> Result<InputSelection> {
    coin_selector.run_bnb(
        Changeless {
            target: ctx.target,
            change_policy: ctx.change_policy,
        },
        BNB_MAX_ROUNDS,
    )?;
    finalize_selection(ctx, &coin_selector, Strategy::Changeless)
}

fn try_lowest_fee_selection(
    ctx: &SelectionContext<'_>,
    mut coin_selector: CoinSelector<'_>,
) -> Result<InputSelection> {
    coin_selector.run_bnb(
        LowestFee {
            target: ctx.target,
            long_term_feerate: ctx.fee_rate,
            change_policy: ctx.change_policy,
        },
        BNB_MAX_ROUNDS,
    )?;
    finalize_selection(ctx, &coin_selector, Strategy::LowestFee)
}

/// 1.0 = implied feerate must match the request (modulo vbyte rounding).
const FEE_RATE_CAP_MAX_OVERSHOOT: f32 = 1.0;

/// Only accepts selections whose implied fee rate stays within the bound;
/// among those, minimizes fee (fewest/cheapest inputs).
struct FeeRateCapMetric {
    target: Target,
    change_policy: ChangePolicy,
    max_overshoot: f32,
}

impl FeeRateCapMetric {
    fn drain_for(cs: &CoinSelector<'_>, target: Target, change_policy: ChangePolicy) -> Drain {
        match cs.drain_value(target, change_policy) {
            Some(value) => Drain {
                weights: change_policy.drain_weights,
                value,
            },
            None => Drain::NONE,
        }
    }

    fn fee_within_cap(&self, cs: &CoinSelector<'_>) -> Option<i64> {
        if !cs.is_target_met(self.target) {
            return None;
        }
        let drain = Self::drain_for(cs, self.target, self.change_policy);
        let fee = cs.fee(self.target.outputs.value_sum, drain.value);
        if fee < 0 {
            return None;
        }
        // Change (or zero leftover) makes fee equal implied_fee. Leftover dumped
        // to miners raises fee above that; max_overshoot 1.0 rejects it.
        // Compare fees, not float feerates: vbyte rounding already lives in
        // implied_fee, so 1.0 stays exact modulo that ceil.
        let max_fee =
            (cs.implied_fee(self.target, drain.weights) as f32 * self.max_overshoot).ceil() as i64;
        if fee > max_fee {
            return None;
        }
        Some(fee)
    }
}

impl BnbMetric for FeeRateCapMetric {
    fn score(&mut self, cs: &CoinSelector<'_>) -> Option<Ordf32> {
        self.fee_within_cap(cs).map(|fee| Ordf32(fee as f32))
    }

    fn bound(&mut self, cs: &CoinSelector<'_>) -> Option<Ordf32> {
        if !cs.is_selection_possible(self.target) {
            return None;
        }
        match self.score(cs) {
            // Already in cap; adding inputs only raises fee.
            Some(score) => Some(score),
            None => Some(Ordf32(0.0)),
        }
    }

    fn requires_ordering_by_descending_value_pwu(&self) -> bool {
        true
    }
}

fn try_fee_rate_cap_selection(
    ctx: &SelectionContext<'_>,
    mut coin_selector: CoinSelector<'_>,
) -> Result<InputSelection> {
    for (index, candidate) in ctx.candidates.iter().enumerate() {
        if !coin_selector.is_selected(index) && candidate.effective_value(ctx.fee_rate) <= 0.0 {
            coin_selector.ban(index);
        }
    }
    coin_selector.run_bnb(
        FeeRateCapMetric {
            target: ctx.target,
            change_policy: ctx.change_policy,
            max_overshoot: FEE_RATE_CAP_MAX_OVERSHOOT,
        },
        BNB_MAX_ROUNDS,
    )?;
    finalize_selection(ctx, &coin_selector, Strategy::FeeRateCap)
}

fn try_greedy_selection(
    ctx: &SelectionContext<'_>,
    mut coin_selector: CoinSelector<'_>,
) -> Result<InputSelection> {
    coin_selector
        .select_until_target_met(ctx.target)
        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
    finalize_selection(ctx, &coin_selector, Strategy::Greedy)
}

fn run_all_strategies(ctx: &SelectionContext<'_>) -> Vec<InputSelection> {
    // every strategy starts from the same base selector, with the mandatory
    // inputs pre-selected, and explores on its own copy
    let base_selector = selector_with_mandatory_inputs(ctx);

    let runners = [
        try_changeless_selection
            as fn(&SelectionContext<'_>, CoinSelector<'_>) -> Result<InputSelection>,
        try_lowest_fee_selection,
        try_fee_rate_cap_selection,
        try_greedy_selection,
    ];

    runners
        .iter()
        .filter_map(|run| run(ctx, base_selector.clone()).ok())
        .collect()
}

/// Run each coin-selection strategy independently on a fresh [`CoinSelector`] clone.
///
/// Returns every strategy that found a valid selection (up to 4). Errors only when all
/// strategies fail.
pub fn pick_utxos_for_fee_rate(
    available_utxos: &[(OutPoint, TxOut)],
    recipients: &[Recipient],
    n_change_outputs: usize,
    fee_rate: FeeRate,
    must_select: &[OutPoint],
) -> Result<Vec<InputSelection>> {
    let (outpoints, candidates) = pool_from_utxos(available_utxos)?;
    let must_select: HashSet<OutPoint> = must_select.iter().copied().collect();

    // A mandatory outpoint that is not in the pool is a caller error: fail
    // loudly here, otherwise every strategy fails downstream and the caller
    // only gets a misleading "Not enough funds available".
    for op in &must_select {
        if !outpoints.contains(op) {
            return Err(anyhow::Error::msg(format!(
                "mandatory input {op} not in the pool"
            )));
        }
    }

    // The dust floor scales with n_change_outputs: the change amount will be split across
    // that many outputs, so each part must stay above the dust threshold.
    let change_policy = ChangePolicy::min_value(
        DrainWeights {
            output_weight: (TXOUT_BASE_WEIGHT + TR_SPK_WEIGHT) * n_change_outputs as u64,
            spend_weight: TR_KEYSPEND_TXIN_WEIGHT * n_change_outputs as u64,
            n_outputs: n_change_outputs,
        },
        TR_DUST_RELAY_MIN_VALUE * 2 * n_change_outputs as u64,
    );

    let target = Target {
        fee: TargetFee::from_feerate(fee_rate),
        outputs: TargetOutputs::fund_outputs(
            recipients
                .iter()
                .map(|r| (recipient_output_weight(r), r.amount.to_sat())),
        ),
    };

    let ctx = SelectionContext {
        outpoints: &outpoints,
        candidates: &candidates,
        must_select: &must_select,
        target,
        change_policy,
        fee_rate,
        n_change_outputs,
    };

    let selections = run_all_strategies(&ctx);
    if selections.is_empty() {
        return Err(anyhow::Error::msg("Not enough funds available"));
    }

    Ok(selections)
}

/// Splits `total` into `n` randomly-sized parts, each at least `min_part`,
/// summing exactly to `total`.
///
/// The split is uniform over all valid compositions (random cut points over
/// the amount exceeding the minimums), avoiding the equal-amount fingerprint
/// of a naive split.
///
/// The RNG is provided by the caller (same philosophy as `aux_rand` in
/// [`SpClient::sign_transaction`](crate::client::SpClient::sign_transaction)):
/// pass `&mut rand::rngs::ThreadRng` for production, a seeded RNG for tests.
///
/// Returns an error if `n == 0` or `total < n * min_part`.
pub fn random_split(
    total: Amount,
    n: usize,
    min_part: Amount,
    rng: &mut impl rand::Rng,
) -> Result<Vec<Amount>> {
    if n == 0 {
        return Err(anyhow::Error::msg("cannot split an amount into 0 outputs"));
    }
    let total_sat = total.to_sat();
    let min_sat = min_part.to_sat();
    let reserved = min_sat.saturating_mul(n as u64);
    if total_sat < reserved {
        return Err(anyhow::Error::msg(format!(
            "cannot split {} into {} outputs of at least {}",
            total, n, min_part
        )));
    }

    // n-1 uniform cut points over the freely distributable remainder.
    let remainder = total_sat - reserved;
    let mut cuts: Vec<u64> = (0..n - 1).map(|_| rng.gen_range(0..=remainder)).collect();
    cuts.sort_unstable();

    let mut parts = Vec::with_capacity(n);
    let mut prev = 0;
    for cut in cuts {
        parts.push(Amount::from_sat(min_sat + cut - prev));
        prev = cut;
    }
    parts.push(Amount::from_sat(min_sat + remainder - prev));
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_coin_select::TR_DUST_RELAY_MIN_VALUE;
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Keypair, PublicKey, TapTweak};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network, ScriptBuf, Txid};

    fn test_fee_rate() -> FeeRate {
        fee_rate_sat_per_vb(1.0)
    }

    fn test_change_outputs() -> usize {
        1
    }

    fn fee_rate_sat_per_vb(sat_per_vb: f32) -> FeeRate {
        FeeRate::from_sat_per_vb(sat_per_vb)
    }

    fn p2tr_txout(value_sat: u64) -> TxOut {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).expect("valid test key");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let tweaked = xonly.tap_tweak(&secp, None).0;
        TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked),
        }
    }

    fn p2pkh_txout(value_sat: u64) -> TxOut {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).expect("valid test key");
        let pk = PublicKey::new(sk.public_key(&secp));
        TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: ScriptBuf::new_p2pkh(&pk.pubkey_hash()),
        }
    }

    fn utxo(value_sat: u64, vout: u32) -> (OutPoint, TxOut) {
        (
            OutPoint::new(Txid::all_zeros(), vout),
            p2tr_txout(value_sat),
        )
    }

    fn foreign_p2pkh(value_sat: u64, vout: u32) -> (OutPoint, TxOut) {
        (
            OutPoint::new(Txid::all_zeros(), vout),
            p2pkh_txout(value_sat),
        )
    }

    fn payment_recipient(value_sat: u64) -> Recipient {
        // Use a distinct key ([0x43; 32]) so payment outputs are never confused with UTXOs.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x43; 32]).expect("valid test key");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let tweaked = xonly.tap_tweak(&secp, None).0;
        let address = Address::p2tr_tweaked(tweaked, Network::Regtest);
        Recipient {
            address: RecipientAddress::LegacyAddress(address.as_unchecked().clone()),
            amount: Amount::from_sat(value_sat),
        }
    }

    fn many_utxos(count: usize, value_sat: u64) -> Vec<(OutPoint, TxOut)> {
        (0..count as u32)
            .map(|vout| utxo(value_sat, vout))
            .collect()
    }

    fn selected_input_sum(utxos: &[(OutPoint, TxOut)], selection: &InputSelection) -> u64 {
        selection
            .selected_utxos
            .iter()
            .map(|op| {
                utxos
                    .iter()
                    .find(|(outpoint, _)| outpoint == op)
                    .map(|(_, txout)| txout.value.to_sat())
                    .expect("selected outpoint must exist in pool")
            })
            .sum()
    }

    fn assert_selection_balances(
        utxos: &[(OutPoint, TxOut)],
        selection: &InputSelection,
        payment_sat: u64,
    ) {
        let input_sum = selected_input_sum(utxos, selection);
        assert_eq!(selection.sent.to_sat(), payment_sat);
        assert_eq!(
            selection.change.to_sat() + selection.fee.to_sat() + selection.sent.to_sat(),
            input_sum,
        );
    }

    fn selection_by_strategy<'a>(
        selections: &'a [InputSelection],
        strategy: Strategy,
    ) -> &'a InputSelection {
        selections
            .iter()
            .find(|selection| selection.strategy == strategy)
            .unwrap_or_else(|| panic!("missing {:?} selection", strategy))
    }

    fn dumps_leftover_to_fee(selection: &InputSelection, requested: FeeRate) -> bool {
        selection.change == Amount::ZERO && selection.actual_fee_rate > requested
    }

    #[test]
    fn select_all_utxos_uses_every_input() {
        let utxos = vec![utxo(100_000, 0), utxo(200_000, 1)];
        let outpoints: Vec<_> = utxos.iter().map(|output| output.0).collect();

        let selection =
            select_all_utxos_for_fee_rate(&utxos, &[], test_fee_rate()).expect("selection");

        assert_eq!(selection.selected_utxos.len(), 2);
        for op in outpoints {
            assert!(selection.selected_utxos.contains(&op));
        }
        assert!(selection.fee > Amount::ZERO);
        // Drain: everything left after fees is sendable, there is no change.
        assert!(selection.sent > Amount::ZERO);
        assert_eq!(selection.change, Amount::ZERO);
        assert_eq!(selection.n_sent_outputs, 0);
        assert_eq!(selection.n_change_outputs, 0);
        assert_eq!(selection.sent + selection.fee, Amount::from_sat(300_000));
    }

    #[test]
    fn select_all_utxos_accounts_for_output_weight() {
        let utxos = vec![utxo(500_000, 0)];
        let recipient = payment_recipient(0);

        let without_outputs =
            select_all_utxos_for_fee_rate(&utxos, &[], test_fee_rate()).expect("selection");
        let with_outputs = select_all_utxos_for_fee_rate(&utxos, &[recipient], test_fee_rate())
            .expect("selection");

        assert_eq!(without_outputs.n_sent_outputs, 0);
        assert_eq!(with_outputs.n_sent_outputs, 1);
        assert!(with_outputs.fee >= without_outputs.fee);
        assert!(with_outputs.sent <= without_outputs.sent);
        assert_eq!(
            with_outputs.sent + with_outputs.fee,
            without_outputs.sent + without_outputs.fee,
        );
    }

    #[test]
    fn select_all_utxos_empty_inputs_fails() {
        let err =
            select_all_utxos_for_fee_rate(&[], &[], test_fee_rate()).expect_err("expected error");
        assert_eq!(err.to_string(), "No funds available");
    }

    #[test]
    fn pick_utxos_prefers_single_input_when_sufficient() {
        let large = utxo(500_000, 0);
        let small = utxo(100_000, 1);
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            &[large.clone(), small],
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
            &[],
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos, vec![large.0]);
        assert!(selection.fee > Amount::ZERO);
    }

    #[test]
    fn pick_utxos_combines_inputs_when_one_is_not_enough() {
        let a = utxo(30_000, 0);
        let b = utxo(30_000, 1);
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            &[a.clone(), b.clone()],
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
            &[],
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos.len(), 2);
        assert!(selection.selected_utxos.contains(&a.0));
        assert!(selection.selected_utxos.contains(&b.0));
        assert_eq!(
            selection.change + selection.fee + Amount::from_sat(50_000),
            Amount::from_sat(60_000),
        );
    }

    #[test]
    fn pick_utxos_always_includes_external_inputs() {
        // Legacy P2PKH-sized input: heavier than TR keyspend, not segwit.
        let external = foreign_p2pkh(10_000, 0);
        let external_outpoint = external.0;
        let owned = utxo(100_000, 1);
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            &[external, owned.clone()],
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
            &[external_outpoint],
        )
        .expect("selection");

        for selection in &selections {
            assert!(selection.selected_utxos.contains(&external_outpoint));
        }

        let tr_external = utxo(10_000, 0);
        let tr_sels = pick_utxos_for_fee_rate(
            &[tr_external.clone(), owned],
            &[payment_recipient(50_000)],
            test_change_outputs(),
            test_fee_rate(),
            &[tr_external.0],
        )
        .expect("tr selection");
        let heavy = selection_by_strategy(&selections, Strategy::LowestFee);
        let light = selection_by_strategy(&tr_sels, Strategy::LowestFee);
        assert!(heavy.fee > light.fee);
    }

    #[test]
    fn pick_utxos_unknown_mandatory_input_fails_loudly() {
        let ghost = OutPoint::new(Txid::all_zeros(), 99);
        let err = pick_utxos_for_fee_rate(
            &[utxo(100_000, 0)],
            &[payment_recipient(50_000)],
            test_change_outputs(),
            test_fee_rate(),
            &[ghost],
        )
        .expect_err("unknown mandatory input must error");
        assert!(err.to_string().contains("mandatory input"));
    }

    #[test]
    fn pick_utxos_emits_change_above_dust_threshold() {
        let utxos = vec![utxo(500_000, 0)];
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            &utxos,
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
            &[],
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        let min_change = TR_DUST_RELAY_MIN_VALUE * 2;
        assert!(
            selection.change == Amount::ZERO || selection.change >= Amount::from_sat(min_change),
            "change {} below dust policy minimum {}",
            selection.change,
            min_change,
        );
        assert_eq!(
            selection.change + selection.fee + Amount::from_sat(50_000),
            Amount::from_sat(500_000),
        );
    }

    /// At 1 sat/vB a single input can fund the payment with no change; at 5 sat/vB the same
    /// input is insufficient, a second input is required, and the excess must become change.
    #[test]
    fn pick_utxos_fee_rate_affects_changeless_vs_change() {
        let low = fee_rate_sat_per_vb(1.0);
        let high = fee_rate_sat_per_vb(5.0);
        let min_change = TR_DUST_RELAY_MIN_VALUE * 2;
        // Sized so 25_250 sats covers payment + fee at 1 sat/vB with no change; at 5 sat/vB
        // that input alone is insufficient and the 2_500 sat top-up is required, which leaves
        // excess above the dust policy (unavoidable change).
        let payment_sat = 25_000;
        let primary_sat = 25_250;
        let second_sat = 2_500;

        let payment = payment_recipient(payment_sat);
        let pool = vec![utxo(primary_sat, 0), utxo(second_sat, 1)];

        let low_sels =
            pick_utxos_for_fee_rate(&pool, &[payment.clone()], test_change_outputs(), low, &[])
                .expect("low fee");
        let low_sel = selection_by_strategy(&low_sels, Strategy::Changeless);
        assert_eq!(low_sel.change, Amount::ZERO);
        assert_eq!(low_sel.selected_utxos, vec![utxo(primary_sat, 0).0]);
        assert_selection_balances(&pool, &low_sel, payment_sat);

        assert!(
            pick_utxos_for_fee_rate(
                &[utxo(primary_sat, 0)],
                &[payment.clone()],
                test_change_outputs(),
                high,
                &[],
            )
            .is_err(),
            "primary input alone must not fund the payment at 5 sat/vB",
        );

        let high_sels =
            pick_utxos_for_fee_rate(&pool, &[payment], test_change_outputs(), high, &[])
                .expect("high fee");
        let high_sel = selection_by_strategy(&high_sels, Strategy::LowestFee);
        assert_eq!(high_sel.selected_utxos.len(), 2);
        assert!(high_sel.selected_utxos.contains(&utxo(primary_sat, 0).0));
        assert!(high_sel.selected_utxos.contains(&utxo(second_sat, 1).0));
        assert!(high_sel.change >= Amount::from_sat(min_change));
        assert_selection_balances(&pool, &high_sel, payment_sat);
    }

    #[test]
    fn pick_utxos_uses_changeless_when_exact_input_exists() {
        let payment_sat = 50_000;
        let fee_rate = test_fee_rate();
        let exact_sat = (payment_sat..payment_sat + 5_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(
                    &[utxo(value_sat, 0), utxo(1_000_000, 1)],
                    &[payment_recipient(payment_sat)],
                    test_change_outputs(),
                    fee_rate,
                    &[],
                )
                .ok()
                .is_some_and(|selections| {
                    selections.iter().any(|selection| {
                        selection.strategy == Strategy::Changeless
                            && selection.change == Amount::ZERO
                            && selection.selected_utxos == vec![utxo(value_sat, 0).0]
                            && !dumps_leftover_to_fee(selection, fee_rate)
                    })
                })
            })
            .expect("a changeless single-input fixture must exist");

        let selections = pick_utxos_for_fee_rate(
            &[utxo(exact_sat, 0), utxo(1_000_000, 1)],
            &[payment_recipient(payment_sat)],
            test_change_outputs(),
            fee_rate,
            &[],
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::Changeless);

        assert_eq!(selection.change, Amount::ZERO);
        assert_eq!(selection.selected_utxos, vec![utxo(exact_sat, 0).0]);

        let cap = selection_by_strategy(&selections, Strategy::FeeRateCap);
        assert_eq!(cap.change, Amount::ZERO);
        assert_eq!(cap.selected_utxos, vec![utxo(exact_sat, 0).0]);
        assert!(!dumps_leftover_to_fee(cap, fee_rate));
    }

    #[test]
    fn pick_utxos_insufficient_funds() {
        let utxos = vec![utxo(1_000, 0)];
        let payment = payment_recipient(1_000_000);

        assert!(
            pick_utxos_for_fee_rate(
                &utxos,
                &[payment],
                test_change_outputs(),
                test_fee_rate(),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn pick_utxos_many_utxos_one_large_covers_payment() {
        let mut utxos = many_utxos(250, 10_000);
        let whale = utxo(10_000_000, 250);
        utxos.push(whale.clone());
        let payment = payment_recipient(100_000);

        let selections = pick_utxos_for_fee_rate(
            &utxos,
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
            &[],
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert_eq!(selection.selected_utxos, vec![whale.0]);
        assert!(selection.selected_utxos.len() < utxos.len());
        assert_selection_balances(&utxos, &selection, 100_000);
    }

    #[test]
    fn pick_utxos_many_utxos_combines_small_inputs() {
        let utxos = many_utxos(200, 10_000);
        let payment = payment_recipient(150_000);

        let selections = pick_utxos_for_fee_rate(
            &utxos,
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
            &[],
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert!(!selection.selected_utxos.is_empty());
        assert!(selection.selected_utxos.len() <= utxos.len());
        assert_selection_balances(&utxos, &selection, 150_000);
        let min_change = TR_DUST_RELAY_MIN_VALUE * 2;
        assert!(
            selection.change == Amount::ZERO || selection.change >= Amount::from_sat(min_change),
        );
    }

    #[test]
    fn pick_utxos_many_utxos_does_not_use_entire_pool() {
        let utxos = many_utxos(300, 50_000);
        let payment = payment_recipient(25_000);

        let selections = pick_utxos_for_fee_rate(
            &utxos,
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
            &[],
        )
        .expect("selection");
        let selection = selection_by_strategy(&selections, Strategy::LowestFee);

        assert!(selection.selected_utxos.len() < utxos.len());
        assert_selection_balances(&utxos, &selection, 25_000);
    }

    #[test]
    fn pick_utxos_many_utxos_insufficient_funds() {
        let utxos = many_utxos(200, 1_000);
        let payment = payment_recipient(500_000);

        assert!(
            pick_utxos_for_fee_rate(
                &utxos,
                &[payment],
                test_change_outputs(),
                test_fee_rate(),
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn pick_utxos_more_change_outputs_never_reduces_fee() {
        let payment_sat = 50_000;
        let utxos = vec![utxo(500_000, 0)];
        let payment = payment_recipient(payment_sat);

        let one_change_sels =
            pick_utxos_for_fee_rate(&utxos, &[payment.clone()], 1, test_fee_rate(), &[])
                .expect("selection with one change output");
        let two_change_sels = pick_utxos_for_fee_rate(&utxos, &[payment], 2, test_fee_rate(), &[])
            .expect("selection with two change outputs");
        let one_change = selection_by_strategy(&one_change_sels, Strategy::LowestFee);
        let two_change = selection_by_strategy(&two_change_sels, Strategy::LowestFee);

        assert_eq!(one_change.selected_utxos, two_change.selected_utxos);
        assert!(two_change.fee >= one_change.fee);
        assert!(two_change.change <= one_change.change);
        assert_selection_balances(&utxos, &one_change, payment_sat);
        assert_selection_balances(&utxos, &two_change, payment_sat);
    }

    #[test]
    fn pick_utxos_two_change_outputs_needs_at_least_as_much_input_value() {
        let payment_sat = 50_000;
        let fee_rate = test_fee_rate();
        let payment = payment_recipient(payment_sat);
        let min_for_one_change = (payment_sat..payment_sat + 50_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(&[utxo(value_sat, 0)], &[payment.clone()], 1, fee_rate, &[])
                    .is_ok()
            })
            .expect("fixture where one change output is affordable");
        let min_for_two_change = (payment_sat..payment_sat + 50_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(&[utxo(value_sat, 0)], &[payment.clone()], 2, fee_rate, &[])
                    .is_ok()
            })
            .expect("fixture where two change outputs are affordable");

        let one_change_sels = pick_utxos_for_fee_rate(
            &[utxo(min_for_one_change, 0)],
            &[payment.clone()],
            1,
            fee_rate,
            &[],
        )
        .expect("one change output should succeed");
        let one_change = selection_by_strategy(&one_change_sels, Strategy::LowestFee);
        assert_selection_balances(&vec![utxo(min_for_one_change, 0)], one_change, payment_sat);

        let two_change_sels =
            pick_utxos_for_fee_rate(&[utxo(min_for_two_change, 0)], &[payment], 2, fee_rate, &[])
                .expect("two change outputs should succeed");
        let two_change = selection_by_strategy(&two_change_sels, Strategy::LowestFee);
        assert_selection_balances(&vec![utxo(min_for_two_change, 0)], two_change, payment_sat);
        assert!(min_for_two_change >= min_for_one_change);
    }

    #[test]
    fn pick_utxos_returns_one_selection_per_successful_strategy() {
        let utxos = vec![utxo(500_000, 0), utxo(100_000, 1)];
        let payment = payment_recipient(50_000);

        let selections = pick_utxos_for_fee_rate(
            &utxos,
            &[payment],
            test_change_outputs(),
            test_fee_rate(),
            &[],
        )
        .expect("selection");

        assert!(selections.len() >= 2);
        assert!(
            selections
                .iter()
                .any(|selection| selection.strategy == Strategy::LowestFee)
        );
        assert!(
            selections
                .iter()
                .any(|selection| selection.strategy == Strategy::FeeRateCap)
        );
        assert!(
            selections
                .iter()
                .any(|selection| selection.strategy == Strategy::Greedy)
        );

        for selection in &selections {
            assert_selection_balances(&utxos, selection, 50_000);
        }
    }

    fn single_input_overpay_sat(payment: &Recipient, fee_rate: FeeRate) -> u64 {
        let payment_sat = payment.amount.to_sat();
        (payment_sat..payment_sat + 5_000)
            .find(|&value_sat| {
                pick_utxos_for_fee_rate(
                    &[utxo(value_sat, 0)],
                    &[payment.clone()],
                    test_change_outputs(),
                    fee_rate,
                    &[],
                )
                .ok()
                .is_some_and(|selections| {
                    selections.iter().any(|selection| {
                        matches!(
                            selection.strategy,
                            Strategy::Changeless | Strategy::Greedy | Strategy::LowestFee
                        ) && dumps_leftover_to_fee(selection, fee_rate)
                    })
                })
            })
            .expect("a single-input overpay fixture must exist")
    }

    /// A single input that funds the payment with leftover below the change
    /// floor. Changeless dumps that leftover into the fee; FeeRateCap should
    /// pull in another input so leftover becomes change.
    #[test]
    fn fee_rate_cap_creates_change_instead_of_overpaying() {
        let fee_rate = test_fee_rate();
        let payment = payment_recipient(50_000);
        let overpay_sat = single_input_overpay_sat(&payment, fee_rate);

        let extra = utxo(10_000, 1);
        let pool = vec![utxo(overpay_sat, 0), extra.clone()];
        let selections =
            pick_utxos_for_fee_rate(&pool, &[payment], test_change_outputs(), fee_rate, &[])
                .expect("selection");
        let cap = selection_by_strategy(&selections, Strategy::FeeRateCap);

        // LowestFee/Changeless/Greedy keep the cheaper single-input dump; only
        // FeeRateCap should spend the extra input to stay at the requested rate.
        for strategy in [Strategy::Changeless, Strategy::LowestFee, Strategy::Greedy] {
            let overpay = selection_by_strategy(&selections, strategy);
            assert!(
                dumps_leftover_to_fee(overpay, fee_rate),
                "{strategy:?} must still dump leftover on this pool"
            );
            assert!(!overpay.selected_utxos.contains(&extra.0));
        }

        assert!(cap.selected_utxos.contains(&extra.0));
        assert!(!dumps_leftover_to_fee(cap, fee_rate));
        // Extra is 10_000 sats; at 1 sat/vB the added input+change output is
        // ~100 sats. If that extra were dumped to fee, change would sit at the
        // dust floor and actual_fee_rate would jump by tens of sat/vB.
        assert!(
            cap.change >= extra.1.value - Amount::from_sat(1_000),
            "extra input was selected but mostly overpaid as fee; change was {}",
            cap.change,
        );
        assert!(cap.actual_fee_rate >= fee_rate);
        assert!(
            cap.actual_fee_rate.as_sat_vb()
                <= fee_rate.as_sat_vb() * FEE_RATE_CAP_MAX_OVERSHOOT + 0.05,
            "FeeRateCap implied {} sat/vB, cap is {} sat/vB",
            cap.actual_fee_rate.as_sat_vb(),
            fee_rate.as_sat_vb() * FEE_RATE_CAP_MAX_OVERSHOOT,
        );
        assert_selection_balances(&pool, cap, 50_000);
    }

    #[test]
    fn fee_rate_cap_absent_when_change_is_impossible() {
        let fee_rate = test_fee_rate();
        let payment = payment_recipient(50_000);
        let overpay_sat = single_input_overpay_sat(&payment, fee_rate);

        let pool = vec![utxo(overpay_sat, 0)];
        let selections =
            pick_utxos_for_fee_rate(&pool, &[payment], test_change_outputs(), fee_rate, &[])
                .expect("selection");

        assert!(
            selections
                .iter()
                .all(|selection| selection.strategy != Strategy::FeeRateCap)
        );
        assert!(!selections.is_empty());
    }

    #[test]
    fn random_split_parts_sum_to_total_and_respect_minimum() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let total = Amount::from_sat(100_000);
        let min = Amount::from_sat(TR_DUST_RELAY_MIN_VALUE * 2);

        for n in 1..=5 {
            let parts = random_split(total, n, min, &mut rng).expect("split");
            assert_eq!(parts.len(), n);
            assert_eq!(parts.iter().copied().sum::<Amount>(), total);
            assert!(parts.iter().all(|&part| part >= min));
        }
    }

    #[test]
    fn random_split_rejects_impossible_splits() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let min = Amount::from_sat(TR_DUST_RELAY_MIN_VALUE * 2);

        assert!(random_split(Amount::from_sat(1_000), 0, min, &mut rng).is_err());
        // 5 * min > total
        assert!(random_split(Amount::from_sat(1_000), 5, min, &mut rng).is_err());
    }

    #[test]
    fn random_split_with_exact_minimum_returns_all_minimums() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let min = Amount::from_sat(TR_DUST_RELAY_MIN_VALUE * 2);

        let parts =
            random_split(Amount::from_sat(min.to_sat() * 4), 4, min, &mut rng).expect("split");
        assert!(parts.iter().all(|&part| part == min));
    }

    #[test]
    fn random_split_produces_uneven_parts() {
        use rand::SeedableRng;
        // Fixed seed: deterministic, but must not be the naive equal split.
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);

        let parts = random_split(Amount::from_sat(100_000), 4, Amount::from_sat(1), &mut rng)
            .expect("split");
        assert!(parts.iter().any(|&part| part != parts[0]));
    }

    #[test]
    fn select_all_utxos_many_inputs() {
        let utxos: Vec<_> = (0..400).map(|vout| utxo(25_000, vout)).collect();
        let outpoints: Vec<_> = utxos.iter().map(|output| output.0).collect();

        let selection =
            select_all_utxos_for_fee_rate(&utxos, &[], test_fee_rate()).expect("selection");

        assert_eq!(selection.selected_utxos.len(), 400);
        for op in outpoints {
            assert!(selection.selected_utxos.contains(&op));
        }
        assert_eq!(selection.change, Amount::ZERO);
        assert_eq!(
            selection.sent + selection.fee,
            Amount::from_sat(400 * 25_000),
        );
    }
}
