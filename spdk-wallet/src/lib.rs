pub mod client;
pub mod scanner;

// re-export traits for consumers who need to provide valid implementors
pub use spdk_core::chain;
pub use spdk_core::updater;

pub use spdk_core::constants::DATA_CARRIER_SIZE;

// re-export blindbit backend if enabled
#[cfg(feature = "backend-blindbit-v1")]
pub use backend_blindbit_v1;

// re-export libraries for consumers
pub use bip321;
pub use bitcoin;
pub use psbt;
pub use silentpayments;
