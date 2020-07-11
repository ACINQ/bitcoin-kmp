# Kotlin Multiplatform Bitcoin Library

 [ ![Download](https://api.bintray.com/packages/acinq/libs/bitcoink/images/download.svg) ](https://bintray.com/acinq/libs/bitcoink/_latestVersion)

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

## Install

First, add the ACINQ libraries repository:

```kotlin
// build.gradle.kts
repositories {
    maven(url = "https://dl.bintray.com/acinq/libs")
}
```

- **Multiplatform**: Add the `fr.acinq.bitcoink:bitcoink` dependency to your common source set dependencies (You need Gradle 5.0 minimum).
- **JVM**: Add the `fr.acinq.bitcoink:bitcoink-jvm` dependency to your project.

## libscp256k1 support

**You need to add a JVM implementation of Secp256k1** to your project in order to use BitcoinK with JVM.

Please refer the [Secp256k1 installation section](https://github.com/ACINQ/secp256k1-kmp#installation).

## Usage

Please have a look at unit tests, more samples will be added soon.
