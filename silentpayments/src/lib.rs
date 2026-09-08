//! A rust implementation of BIP352: Silent Payments. This library
//! can be used to add silent payment support to wallets.
//!
//! ## Feature Flags
//!
//! This library offers granular feature flags to minimize dependencies:
//!
//! - **default**: Enables `encode`, `sending`, and `receiving` features
//! - **encode**: Enables string encoding/decoding for `SilentPaymentCode` (requires `bech32`)
//! - **serde**: Enables serde serialization/deserialization for types
//! - **sending**: Enables sending functionality (requires `bitcoin_hashes`, `hex`, and `encode`)
//! - **receiving**: Enables receiving functionality (requires `bitcoin_hashes`, `hex`, `serde`, and `encode`)
//!
//! ### Minimal Usage
//!
//! If you only need the type definitions (`Network` and `SilentPaymentKeyMaterial`) without
//! any additional functionality, you can disable all default features:
//!
//! ```toml
//! [dependencies]
//! silentpayments = { version = "0.4", default-features = false }
//! ```
//!
//! This will only pull in `secp256k1` as a dependency, giving you access to the core types
//! without any encoding, serialization, or protocol functionality.
//!
//! **Note**: Without the `encode` feature, construct a [`SilentPaymentKeyMaterial`] from
//! parsed pubkeys using [`SilentPaymentKeyMaterial::new`]. With `encode`, use
//! [`SilentPaymentCode`] for bech32m strings (see [`SilentPaymentCode::new`]
//! for the on-wire format if you parse bech32 yourself).
//!
//! ## Examples
//!
//! Will be added soon.
//! In the meantime, have a look at the [test vectors from the BIP](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs)
//! to see how to do a simple implementation.
//!
//! Alternatively, have a look at [Sp client](https://github.com/cygnet3/sp-client/tree/master),
//! which is a WIP wallet client for building silent payment wallets.
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
#[cfg(feature = "encode")]
pub use utils::common::SilentPaymentCode;
pub use utils::common::SilentPaymentKeyMaterial;
pub use utils::common::SpVersion;
#[cfg(any(feature = "sending", feature = "receiving"))]
pub use utils::common::TransactionInputs;
#[cfg(any(feature = "sending", feature = "receiving"))]
pub use utils::common::TransactionSharedSecret;

pub type Result<T> = std::result::Result<T, Error>;
