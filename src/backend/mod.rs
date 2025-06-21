mod backend;
#[cfg(feature = "blindbit-backend")]
mod blindbit;
mod structs;

pub use backend::ChainBackend;

#[cfg(target_arch = "wasm32")]
pub use backend::ChainBackendWasm;

pub use structs::*;

#[cfg(feature = "blindbit-backend")]
pub use blindbit::BlindbitBackend;

#[cfg(feature = "blindbit-backend")]
pub use blindbit::BlindbitClient;
