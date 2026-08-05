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

import fr.acinq.bitcoin.MnemonicCode.toMnemonics
import fr.acinq.bitcoin.MnemonicCode.toSeed
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class MnemonicCodeTestsCommon {
    @Test
    fun `to seed`() {
        val mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val passphrase = ""
        val seed = MnemonicCode.toSeed(mnemonics, passphrase)
        assertEquals(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            Hex.encode(seed)
        )
    }

    @Test
    fun `reference tests`() {
        val tests = TestHelpers.readResourceAsJson("bip39/vectors.json")
        val wordlists = mapOf(
            "chinese_simplified" to TestHelpers.readResourceAsLines("bip39/chinese_simplified.txt"),
            "chinese_traditional" to TestHelpers.readResourceAsLines("bip39/chinese_traditional.txt"),
            "czech" to TestHelpers.readResourceAsLines("bip39/czech.txt"),
            "english" to MnemonicCode.englishWordlist,
            "french" to TestHelpers.readResourceAsLines("bip39/french.txt"),
            "italian" to TestHelpers.readResourceAsLines("bip39/italian.txt"),
            "japanese" to TestHelpers.readResourceAsLines("bip39/japanese.txt"),
            "korean" to TestHelpers.readResourceAsLines("bip39/korean.txt"),
            "portuguese" to TestHelpers.readResourceAsLines("bip39/portuguese.txt"),
            "spanish" to TestHelpers.readResourceAsLines("bip39/spanish.txt"),
        )
        tests.jsonObject.forEach {
            val language = it.key
            val wordlist = wordlists[language] ?: return@forEach
            it.value.jsonArray.forEach {
                val raw = it.jsonArray[0].jsonPrimitive.content
                // expected mnemonic words in test vectors are separated by white spaces except for Japanese test vectors that use Japanese full-width spaces (U+3000)
                val expectedMnemonics = it.jsonArray[1].jsonPrimitive.content.split(Regex("[ \\t\\n\\r\\u3000]+"))
                val expectedSeed = it.jsonArray[2].jsonPrimitive.content
                val expectedXpriv = it.jsonArray[3].jsonPrimitive.content
                val mnemonics = toMnemonics(Hex.decode(raw), wordlist)
                assertEquals(expectedMnemonics, mnemonics, "$language test vectors")
                val seed = toSeed(mnemonics, passphrase = "TREZOR")
                assertEquals(expectedSeed, Hex.encode(seed), "$language test vectors")
                val xpriv = DeterministicWallet.generate(seed)
                assertEquals(expectedXpriv, xpriv.encode(DeterministicWallet.xprv), "$language test vectors")
            }
        }
    }

    @Test
    fun `validate mnemonics -- valid`() {
        val random = Random

        for (i in 0..99) {
            for (length in listOf(16, 20, 24, 28, 32, 36, 40)) {
                val entropy = ByteArray(length)
                random.nextBytes(entropy)
                val mnemonics = toMnemonics(entropy)
                MnemonicCode.validate(mnemonics)
            }
        }
    }

    @Test
    fun `validate mnemonics -- invalid`() {
        val invalidMnemonics = listOf(
            "",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow", // one word missing
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog fog", // one extra word
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fig" // wrong word
        )
        invalidMnemonics.map {
            assertFails {
                MnemonicCode.validate(it)
            }
        }
    }
}