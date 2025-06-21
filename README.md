# SP client

Sp-client is a library that can be used to build silent payment wallets.
It builds on top of [rust-silentpayments](https://github.com/cygnet3/rust-silentpayments).

Whereas rust-silentpayments concerns itself with cryptography (it is essentially a wrapper around secp256k1 for some silent payments logic),
sp-client is concerned with high-level wallet stuff, such as parsing incoming transactions, managing owned outputs, and signing transactions.

This library is used as a backend for the silent payment wallet [Dana wallet](https://github.com/cygnet3/danawallet).

## WASM Support

This library supports WebAssembly (WASM) targets for use in web applications. To build for WASM:

### Prerequisites

1. Install the WASM target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. Install wasm-pack (optional, for easier WASM builds):
   ```bash
   cargo install wasm-pack
   ```

### Building for WASM

#### Using Cargo directly:
```bash
cargo build --target wasm32-unknown-unknown
```

#### Using wasm-pack:
```bash
wasm-pack build --target web
```

### Features

When building for WASM:
- The `rayon` dependency is automatically disabled and parallel processing falls back to sequential processing
- The `blindbit-backend` feature is available but requires appropriate HTTP client configuration for WASM
- All core functionality remains available

### Usage in Web Applications

The library can be used in web applications through standard WASM interop. Note that some features like the `blindbit-backend` may require additional configuration for HTTP requests in the browser environment.
