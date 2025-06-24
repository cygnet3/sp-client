mod backend;
#[cfg(feature = "blindbit-backend")]
mod blindbit;
mod structs;

#[cfg(target_arch = "wasm32")]
pub use backend::ChainBackendWasm;

#[cfg(not(target_arch = "wasm32"))]
pub use backend::ChainBackend;

pub use structs::*;

#[cfg(feature = "blindbit-backend")]
pub use blindbit::BlindbitBackend;

#[cfg(feature = "blindbit-backend")]
pub use blindbit::BlindbitClient;
