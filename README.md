# SP client

Sp-client is a library that can be used to build silent payment wallets.
It builds on top of [rust-silentpayments](https://github.com/cygnet3/rust-silentpayments).

Whereas rust-silentpayments concerns itself with cryptography (it is essentially a wrapper around secp256k1 for some silent payments logic),
sp-client is concerned with high-level wallet stuff, such as parsing incoming transactions, managing owned outputs, and signing transactions.
