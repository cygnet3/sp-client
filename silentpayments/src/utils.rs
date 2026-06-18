//! Utility functions for both sending and receiving.
//!
//! This module contains functions that are more 'high-level'
//! than the basic sending and receiving logic.
#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) mod hash;
#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) mod script;
#[cfg(all(
    feature = "sending",
    any(feature = "dleq-standalone", feature = "dleq-native")
))]
pub mod sending;

pub(crate) mod common;

#[cfg(any(feature = "sending", feature = "receiving"))]
pub use common::OutPoint;

/// [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)-defined 'Nothing Up My Sleeve' point.
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Taproot witness annex prefix byte ([BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)).
pub(crate) const TAPROOT_ANNEX_PREFIX: u8 = 0x50;

// Define OP_CODES used in script template matching for readability
pub(crate) const OP_0: u8 = 0x00;
pub(crate) const OP_PUSHBYTES_1: u8 = 0x01;
pub(crate) const OP_PUSHBYTES_20: u8 = 0x14;
pub(crate) const OP_PUSHBYTES_32: u8 = 0x20;
pub(crate) const OP_PUSHBYTES_75: u8 = 0x4b;
pub(crate) const OP_1: u8 = 0x51;
pub(crate) const OP_PUSHDATA1: u8 = 0x4c;
pub(crate) const OP_PUSHDATA2: u8 = 0x4d;
pub(crate) const OP_PUSHDATA4: u8 = 0x4e;
pub(crate) const OP_HASH160: u8 = 0xA9;
pub(crate) const OP_EQUAL: u8 = 0x87;
pub(crate) const OP_DUP: u8 = 0x76;
pub(crate) const OP_EQUALVERIFY: u8 = 0x88;
pub(crate) const OP_CHECKSIG: u8 = 0xAC;

// Only compressed pubkeys are supported for silent payments
const COMPRESSED_PUBKEY_SIZE: usize = 33;

// Derivation paths according to BIP
pub const MAIN_SCAN_PATH: &str = "m/352h/0h/0h/1h/0";
pub const MAIN_SPEND_PATH: &str = "m/352h/0h/0h/0h/0";
pub const TEST_SCAN_PATH: &str = "m/352h/1h/0h/1h/0";
pub const TEST_SPEND_PATH: &str = "m/352h/1h/0h/0h/0";
