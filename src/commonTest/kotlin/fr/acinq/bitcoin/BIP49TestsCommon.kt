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

import fr.acinq.bitcoin.Bitcoin.computeBIP49Address
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

class BIP49TestsCommon {
    @Test
    fun `BIP49 reference tests`() {
        val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "), "")
        val master = DeterministicWallet.generate(seed)
        assertEquals(DeterministicWallet.encode(master, DeterministicWallet.tprv), "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd")

        val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/49'/1'/0'"))
        assertEquals(DeterministicWallet.encode(accountKey, DeterministicWallet.tprv), "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY")

        val key = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 0L))
        assertEquals(key.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/49'/1'/0'/0/0")).secretkeybytes)
        assertEquals(key.privateKey.toBase58(Base58.Prefix.SecretKeyTestnet), "cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ")
        assertEquals(
            key.privateKey,
            PrivateKey(Hex.decode("c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e801"))
        )
        assertEquals(
            key.publicKey,
            PublicKey(Hex.decode("03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"))
        )
        assertEquals(computeBIP49Address(key.publicKey, Block.TestnetGenesisBlock.hash), "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2")
    }
}