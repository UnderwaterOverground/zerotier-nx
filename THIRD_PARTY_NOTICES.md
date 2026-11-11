# Third-party notices

zerotier-nx is built from the following third-party code. Their licences
apply to the parts they cover; see each project for the full text.

## Bundled or linked into the console binaries

| Component | Licence | Where |
|---|---|---|
| [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere) libstratosphere / libvapours (1.12.0) | GPL-2.0 | `third_party/Atmosphere` (submodule); linked into the sysmodule |
| [libtesla](https://github.com/WerWolv/libtesla) | GPL-2.0 | `third_party/libtesla` (submodule); the overlay |
| [libnx](https://github.com/switchbrew/libnx) | ISC | devkitPro; all console binaries |
| [ZeroTier](https://github.com/zerotier/ZeroTierOne) core, 1.16.2 (`node/` and `include/` only) | MPL-2.0 | `third_party/ZeroTierOne` (submodule), built with the changes in `patches/zerotier-*.patch` (listed in `VENDORED.md`); linked into the sysmodule. MPL-2.0 allows combining with GPL-2.0 code (its section 3.3); the patched files stay under MPL-2.0 |
| [LZ4](https://github.com/lz4/lz4) 1.7.5 | BSD-2-Clause | inside ZeroTier's `node/Packet.cpp`; only decompression is used |

## Rust crates in the sysmodule

Generated from `cargo tree -p ztnx-ffi -e normal --target all`. Where a crate
offers a choice of licences, zerotier-nx uses it under the MIT, BSD or ISC
option, all of which are compatible with GPL-2.0.

| Crate | Version | Licence |
|---|---|---|
| [aead](https://github.com/RustCrypto/traits) | 0.5.2 | MIT OR Apache-2.0 |
| [base16ct](https://github.com/RustCrypto/formats/tree/master/base16ct) | 0.2.0 | Apache-2.0 OR MIT |
| [bitflags](https://github.com/bitflags/bitflags) | 1.3.2 | MIT/Apache-2.0 |
| [block-buffer](https://github.com/RustCrypto/utils) | 0.10.4 | MIT OR Apache-2.0 |
| [byteorder](https://github.com/BurntSushi/byteorder) | 1.5.0 | Unlicense OR MIT |
| [cfg-if](https://github.com/rust-lang/cfg-if) | 1.0.5 | MIT OR Apache-2.0 |
| [chacha20](https://github.com/RustCrypto/stream-ciphers) | 0.9.1 | Apache-2.0 OR MIT |
| [chacha20poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) | 0.10.1 | Apache-2.0 OR MIT |
| [cipher](https://github.com/RustCrypto/traits) | 0.4.4 | MIT OR Apache-2.0 |
| [const-oid](https://github.com/RustCrypto/formats/tree/master/const-oid) | 0.9.6 | Apache-2.0 OR MIT |
| [cpufeatures](https://github.com/RustCrypto/utils) | 0.2.17 | MIT OR Apache-2.0 |
| [cpufeatures](https://github.com/RustCrypto/utils) | 0.3.1 | MIT OR Apache-2.0 |
| [crypto-bigint](https://github.com/RustCrypto/crypto-bigint) | 0.5.5 | Apache-2.0 OR MIT |
| [crypto-common](https://github.com/RustCrypto/traits) | 0.1.7 | MIT OR Apache-2.0 |
| [curve25519-dalek-derive](https://github.com/dalek-cryptography/curve25519-dalek) | 0.1.1 | MIT/Apache-2.0 |
| [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek) | 5.0.0 | BSD-3-Clause |
| [der](https://github.com/RustCrypto/formats/tree/master/der) | 0.7.10 | Apache-2.0 OR MIT |
| [digest](https://github.com/RustCrypto/traits) | 0.10.7 | MIT OR Apache-2.0 |
| [ecdsa](https://github.com/RustCrypto/signatures/tree/master/ecdsa) | 0.16.9 | Apache-2.0 OR MIT |
| [elliptic-curve](https://github.com/RustCrypto/traits/tree/master/elliptic-curve) | 0.13.8 | Apache-2.0 OR MIT |
| [ff](https://github.com/zkcrypto/ff) | 0.13.1 | MIT/Apache-2.0 |
| [fiat-crypto](https://github.com/mit-plv/fiat-crypto) | 0.3.0 | MIT OR Apache-2.0 OR BSD-1-Clause |
| [generic-array](https://github.com/fizyk20/generic-array.git) | 0.14.7 | MIT |
| [group](https://github.com/zkcrypto/group) | 0.13.0 | MIT/Apache-2.0 |
| [hash32](https://github.com/japaric/hash32) | 0.3.1 | MIT OR Apache-2.0 |
| [heapless](https://github.com/rust-embedded/heapless) | 0.9.3 | MIT OR Apache-2.0 |
| [hmac](https://github.com/RustCrypto/MACs) | 0.12.1 | MIT OR Apache-2.0 |
| [inout](https://github.com/RustCrypto/utils) | 0.1.4 | MIT OR Apache-2.0 |
| [lazy_static](https://github.com/rust-lang-nursery/lazy-static.rs) | 1.5.1 | MIT OR Apache-2.0 |
| [libc](https://github.com/rust-lang/libc) | 0.2.189 | MIT OR Apache-2.0 |
| [libm](https://github.com/rust-lang/compiler-builtins) | 0.2.16 | MIT |
| [log](https://github.com/rust-lang/log) | 0.4.34 | MIT OR Apache-2.0 |
| [managed](https://github.com/m-labs/rust-managed.git) | 0.8.0 | 0BSD |
| [num-bigint-dig](https://github.com/dignifiedquire/num-bigint) | 0.8.6 | MIT/Apache-2.0 |
| [num-integer](https://github.com/rust-num/num-integer) | 0.1.47 | MIT OR Apache-2.0 |
| [num-iter](https://github.com/rust-num/num-iter) | 0.1.46 | MIT OR Apache-2.0 |
| [num-traits](https://github.com/rust-num/num-traits) | 0.2.19 | MIT OR Apache-2.0 |
| [once_cell](https://github.com/matklad/once_cell) | 1.21.4 | MIT OR Apache-2.0 |
| [opaque-debug](https://github.com/RustCrypto/utils) | 0.3.1 | MIT OR Apache-2.0 |
| [p256](https://github.com/RustCrypto/elliptic-curves/tree/master/p256) | 0.13.2 | Apache-2.0 OR MIT |
| [p384](https://github.com/RustCrypto/elliptic-curves/tree/master/p384) | 0.13.1 | Apache-2.0 OR MIT |
| [pkcs1](https://github.com/RustCrypto/formats/tree/master/pkcs1) | 0.7.5 | Apache-2.0 OR MIT |
| [pkcs8](https://github.com/RustCrypto/formats/tree/master/pkcs8) | 0.10.2 | Apache-2.0 OR MIT |
| [poly1305](https://github.com/RustCrypto/universal-hashes) | 0.8.0 | Apache-2.0 OR MIT |
| [ppv-lite86](https://github.com/cryptocorrosion/cryptocorrosion) | 0.2.21 | MIT OR Apache-2.0 |
| [primeorder](https://github.com/RustCrypto/elliptic-curves/tree/master/primeorder) | 0.13.6 | Apache-2.0 OR MIT |
| [proc-macro2](https://github.com/dtolnay/proc-macro2) | 1.0.107 | MIT OR Apache-2.0 |
| [quote](https://github.com/dtolnay/quote) | 1.0.47 | MIT OR Apache-2.0 |
| [rand](https://github.com/rust-random/rand) | 0.8.8 | MIT OR Apache-2.0 |
| [rand_chacha](https://github.com/rust-random/rand) | 0.3.1 | MIT OR Apache-2.0 |
| [rand_core](https://github.com/rust-random/rand) | 0.6.4 | MIT OR Apache-2.0 |
| [rand_core](https://github.com/rust-random/rand_core) | 0.10.1 | MIT OR Apache-2.0 |
| [rfc6979](https://github.com/RustCrypto/signatures/tree/master/rfc6979) | 0.4.0 | Apache-2.0 OR MIT |
| [rsa](https://github.com/RustCrypto/RSA) | 0.9.10 | MIT OR Apache-2.0 |
| [rustls-pki-types](https://github.com/rustls/pki-types) | 1.15.1 | MIT OR Apache-2.0 |
| [rustls-webpki](https://github.com/rustls/webpki) | 0.103.15 | ISC |
| [rustls](https://github.com/rustls/rustls) | 0.23.45 | Apache-2.0 OR ISC OR MIT |
| [sec1](https://github.com/RustCrypto/formats/tree/master/sec1) | 0.7.3 | Apache-2.0 OR MIT |
| [sha2](https://github.com/RustCrypto/hashes) | 0.10.9 | MIT OR Apache-2.0 |
| [signature](https://github.com/RustCrypto/traits/tree/master/signature) | 2.2.0 | Apache-2.0 OR MIT |
| [smallvec](https://github.com/servo/rust-smallvec) | 1.16.2 | MIT OR Apache-2.0 |
| [smoltcp](https://github.com/smoltcp-rs/smoltcp.git) | 0.14.0 | 0BSD |
| [spin](https://github.com/mvdnes/spin-rs.git) | 0.9.9 | MIT |
| [spki](https://github.com/RustCrypto/formats/tree/master/spki) | 0.7.3 | Apache-2.0 OR MIT |
| [stable_deref_trait](https://github.com/storyyeller/stable_deref_trait) | 1.2.1 | MIT OR Apache-2.0 |
| [subtle](https://github.com/dalek-cryptography/subtle) | 2.6.1 | BSD-3-Clause |
| [syn](https://github.com/dtolnay/syn) | 2.0.119 | MIT OR Apache-2.0 |
| [typenum](https://github.com/paholg/typenum) | 1.20.1 | MIT OR Apache-2.0 |
| [unicode-ident](https://github.com/dtolnay/unicode-ident) | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| [universal-hash](https://github.com/RustCrypto/traits) | 0.5.1 | MIT OR Apache-2.0 |
| [untrusted](https://github.com/briansmith/untrusted) | 0.9.0 | ISC |
| [x25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek) | 3.0.0 | BSD-3-Clause |
| [zerocopy-derive](https://github.com/google/zerocopy) | 0.8.59 | BSD-2-Clause OR Apache-2.0 OR MIT |
| [zerocopy](https://github.com/google/zerocopy) | 0.8.59 | BSD-2-Clause OR Apache-2.0 OR MIT |
| [zeroize](https://github.com/RustCrypto/utils) | 1.9.0 | Apache-2.0 OR MIT |
