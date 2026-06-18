#![doc = include_str!("../README.md")]
#![allow(dead_code, non_snake_case)]

#[cfg(all(
    feature = "sending",
    not(any(feature = "dleq-standalone", feature = "dleq-native"))
))]
compile_error!(
    "The `sending` feature requires either `dleq-standalone` or `dleq-native` to select a DLEQ backend."
);

mod error;

#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(all(
    feature = "sending",
    any(feature = "dleq-standalone", feature = "dleq-native")
))]
pub mod sending;
pub mod utils;

#[cfg(any(feature = "sending", feature = "receiving"))]
pub use bitcoin_hashes;
pub use secp256k1;

pub use crate::error::Error;
#[cfg(all(
    feature = "sending",
    any(feature = "dleq-standalone", feature = "dleq-native")
))]
pub use rust_dleq::DleqProof;
pub use utils::common::Network;
#[cfg(feature = "encode")]
pub use utils::common::SilentPaymentCode;
pub use utils::common::SilentPaymentKeyMaterial;
pub use utils::common::SpVersion;
#[cfg(any(feature = "sending", feature = "receiving"))]
pub use utils::common::{NonEmptyArray, TransactionInputs, TransactionSharedSecret};

pub type Result<T> = std::result::Result<T, Error>;
