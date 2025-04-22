### BLS Signature Aggregation Mini
This project demonstrates a minimal implementation of BLS signature aggregation, inspired by how Ethereum uses BLS signatures.

Developed it as a fun way of using BLS : )

### Features
- BLS key generation (SecretKey, PublicKey)

- Message signing with domain separation

- Signature aggregation across multiple validators

- Aggregate signature verification

- Simple mock validator model


### Output
On running, it simulates a set of validators signing a common message (like a slot hash). 
```rust
cargo run
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running 
Aggregated signature is valid: true
```
Additionally the test results can be found in `bls-signature.txt`.
