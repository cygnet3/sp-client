#![doc = include_str!("../README.md")]
#![allow(dead_code, non_snake_case)]
mod error;

#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(feature = "sending")]
pub mod sending;
pub mod utils;

#[cfg(any(feature = "sending", feature = "receiving"))]
pub use bitcoin_hashes;
pub use secp256k1;

pub use crate::error::Error;
pub use utils::common::Network;
#[cfg(any(feature = "sending", feature = "receiving"))]
pub use utils::common::SharedSecret;
#[cfg(feature = "encode")]
pub use utils::common::SilentPaymentCode;
pub use utils::common::SilentPaymentKeyMaterial;
pub use utils::common::SpVersion;
#[cfg(any(feature = "sending", feature = "receiving"))]
pub use utils::common::TransactionInputs;

pub type Result<T> = std::result::Result<T, Error>;
