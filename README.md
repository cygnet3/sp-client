# SP backend

This is the silent payments backend for our flutter silent payments wallet [Donationwallet](https://github.com/cygnet3/donationwallet).

Our wallet uses nakamoto (a BIP158 client) and rust-silentpayments. To communicate with flutter, we use flutter\_rust\_bridge.

## Generate binaries for android

Generating the binaries for android requires installing `cargo-ndk`. Install it by running `cargo install cargo-ndk`. You may also need to add your desired toolchains:

```
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android
```

After these are installed, run `just build-android` (or just copy the command found in the `justfile`).

## Updating flutter api

To bridge between flutter and rust, the interface in `src/api.rs` is exposed to flutter. Whenever this file is updated, you need to run `flutter_rust_bridge_codegen`. First install it using `cargo install flutter_rust_bridge_codegen`, then run `just gen` (or copy the command found in the `justfile`.
