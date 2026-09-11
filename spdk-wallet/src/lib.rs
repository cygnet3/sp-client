pub mod client;
pub mod scanner;

// re-export traits for consumers who need to provide valid implementors
pub use spdk_core::chain;
pub use spdk_core::updater;

// re-export blindbit backend if enabled
#[cfg(feature = "backend-blindbit-v1")]
pub use backend_blindbit_v1;

// re-export frigate backend if enabled
#[cfg(feature = "backend-frigate")]
pub use backend_frigate;

// re-export libraries for consumers
pub use bip321;
pub use bitcoin;
pub use silentpayments;
