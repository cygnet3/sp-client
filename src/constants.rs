pub const PSBT_SP_PREFIX: &str = "sp";
pub const PSBT_SP_SUBTYPE: u8 = 0;
pub const PSBT_SP_TWEAK_KEY: &str = "tweak";
pub const PSBT_SP_ADDRESS_KEY: &str = "address";

pub const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

// This threshold is used during change address creation.
// If the change amount is below this number, we don't bother making a change address.
// Instead, the funds will be added to the transaction fee.
pub const DUST_THRESHOLD: bitcoin::Amount = bitcoin::Amount::from_sat(546);

pub const DATA_CARRIER_SIZE: usize = 205;
