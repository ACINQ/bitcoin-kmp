# Kotlin Multiplatform Bitcoin Library

## Overview

This is a simple Kotlin Multiplatform library which implements most of the bitcoin protocol:

* base58 encoding/decoding
* block headers, block and tx parsing
* tx creation, signature and verification
* script parsing and execution (including OP_CLTV and OP_CSV)
* pay to public key tx
* pay to script tx / multisig tx
* BIP 32 (deterministic wallets)
* BIP 39 (mnemonic code for generating deterministic keys)
* BIP 173 (Base32 address format for native v0-16 witness outputs)

## Objectives

Our goal is not to re-implement a full Bitcoin node but to build a library that implements all the primitives that you need to create bitcoin applications: building and signing transactions, verifying transactions, working with custom bitcoin scripts, parsing blocks, headers, transactions, building BIP39 wallets, ... 

Our runtime targets are:
- JVM
- Android
- iOS
- Linux 64 bits (for testing/prototyping only ! just use the JVM for production applications)

## Status
- [X] Message parsing (blocks, transactions, inv, ...)
- [X] Building transactions (P2PK, P2PKH, P2SH, P2WPK, P2WSH)
- [X] Signing transactions
- [X] Verifying signatures
- [X] Passing core reference tests (scripts & transactions)
- [X] Passing core reference segwit tests

## libscp256k1 support

### Native targets (iOS, linux64)

Native targets include libsecp256k1, called through KMP's c-interop, you don't have anything to do.

### JVM target

The JVM library uses JNI bindings for libsecp256k1, which is must faster than BouncyCastle. It will extract and load native bindings for your operating system in a temporary directory. If this process fails it will fallback to BouncyCastle.

JNI libraries are included for:
- Linux 64 bits
- Windows 64 bits
- Macos 64 bits

If you are using the JVM on an OS for which we don't provide JNI bindings (32 bits OS for example), you can use your own library native library by specifying its path with `-Dfr.acinq.secp256k1.lib.path` and optionally its name with `-Dfr.acinq.secp256k1.lib.name` (if unspecified
bitcoink use the standard name for your OS i.e. libsecp256k1.so on Linux, secp256k1.dll on Windows, ...)

You can also specify the temporary directory where the library will be extracted with `-Djava.io.tmpdir` or `-Dfr.acinq.secp256k1.tmpdir` (if you want to use a different
directory from `-Djava.io.tmpdir`).

## Usage

Please have a look at unit tests, more samples will be added soon.
