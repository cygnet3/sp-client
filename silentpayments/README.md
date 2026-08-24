# Silent Payments

A rust implementation of BIP352: Silent Payments.

## About

This library supports creating and sending to silent payment codes,
building on [`secp256k1`](https://docs.rs/secp256k1/latest/secp256k1)
`PublicKey` and `SecretKey` structs for the interface.
In the future, the library will probably be expanded to rely on structs from rust-bitcoin as well.

## Feature Flags

This library offers granular feature flags to minimize dependencies:

- **default**: Enables all features (`encode`, `sending`, `receiving`)
- **encode**: Enables string encoding/decoding for `SilentPaymentCode` (requires `bech32`)
- **serde**: Enables serde serialization/deserialization for types
- **sending**: Enables sending functionality (requires `bitcoin_hashes`, `hex` and `encode`)
- **receiving**: Enables receiving functionality (requires `bitcoin_hashes`, `hex`,`serde` and `encode`)

### Minimal Usage

If you only need the type definitions ([`Network`] and [`SilentPaymentKeyMaterial`]) without any protocol functionality, you can disable all default features:

```toml
[dependencies]
silentpayments = { version = "0.7", default-features = false }
```

This will only pull `secp256k1` as a dependency, giving you access to the core types without any encoding, serialization, or protocol functionality.

## Sending

For sending to silent payment recipients, build a `TransactionSharedSecret` per recipient scan key using `GlobalSenderEcdhShare` (single signer) or `PartialSenderEcdhShare` (collaborative), then call `sending::generate_recipient_pubkeys` with the recipient key material and the shared secrets map.

## Receiving

For receiving silent payments, we use the [`Receiver`](`receiving::Receiver`) struct.
This [`Receiver`](receiving::Receiver) implements a [`scan_transaction`](receiving::Receiver::scan_transaction) function that can be used to scan an incoming transaction for newly received payments.

The library also supports labels.
The change label (label for generating change codes) is included by default.
You can add additional labels before scanning by using the [`add_label`](receiving::Receiver::add_label) function.

## Examples

Check out the `examples` folder for some simple sending and receiving examples.

For a more realistic example, we recommend having a look at `spdk-wallet`.
This library is part of a monorepo called [SPDK](https://github.com/cygnet3/spdk) (Silent Payments Development Kit).
`spdk-wallet` builds on top of this library to perform wallet-related operations such as scanning for incoming payments and constructing and signing outgoing transactions.
`spdk-wallet` might therefore be a good reference for how this library can be used to integrate silent payments into existing wallets.

## Tests

The `tests/resources` folder contains a copy of the test vectors as of May 1st 2024.

You can test the code using the test vectors by running `cargo test`.

## Changelog

<details>

<summary>Expand</summary>

### v0.7.0

- Add public constants for scan / spend key paths
- Rename getters: drop `get-` prefixes
- Split `SilentPaymentAddress` into 2 separate structs: [`SilentPaymentCode`] and [`SilentPaymentKeyMaterial`]. [`SilentPaymentCode`] represents the encodable silent payment address, the key material struct is used for performing the bip352-related calculations.

</details>
