/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.bitcoin

import fr.acinq.bitcoin.Bitcoin.computeBIP84Address
import kotlin.test.Test
import kotlin.test.assertEquals

class BIP84TestsCommon {
    /**
     * BIP 84 (Derivation scheme for P2WPKH based accounts) reference tests
     * see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
     */
    @Test
    fun `BIP49 reference tests`() {
        val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "), "")
        val master = DeterministicWallet.generate(seed)
        assertEquals(DeterministicWallet.encode(master, DeterministicWallet.zprv), "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.zpub), "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF")

        val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'"))
        assertEquals(DeterministicWallet.encode(accountKey, DeterministicWallet.zprv), "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.zpub), "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")

        val key = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 0L))
        assertEquals(key.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'/0/0")).secretkeybytes)
        assertEquals(key.privateKey.toBase58(Base58.Prefix.SecretKey), "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d")
        assertEquals(
            key.publicKey,
            PublicKey.fromHex("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c")
        )
        assertEquals(computeBIP84Address(key.publicKey, Block.LivenetGenesisBlock.hash), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")

        val key1 = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 1L))
        assertEquals(key1.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'/0/1")).secretkeybytes)
        assertEquals(key1.privateKey.toBase58(Base58.Prefix.SecretKey), "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy")
        assertEquals(
            key1.publicKey,
            PublicKey.fromHex("03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77")
        )
        assertEquals(computeBIP84Address(key1.publicKey, Block.LivenetGenesisBlock.hash), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")

        val key2 = DeterministicWallet.derivePrivateKey(accountKey, listOf(1L, 0L))
        assertEquals(key2.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'/1/0")).secretkeybytes)
        assertEquals(key2.privateKey.toBase58(Base58.Prefix.SecretKey), "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF")
        assertEquals(
            key2.publicKey,
            PublicKey.fromHex("03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6")
        )
        assertEquals(computeBIP84Address(key2.publicKey, Block.LivenetGenesisBlock.hash), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")
    }
}