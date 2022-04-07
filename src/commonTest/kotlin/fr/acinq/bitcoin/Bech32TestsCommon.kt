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

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails

class Bech32TestsCommon {
    @Test
    fun `valid checksums`() {
        val inputs = listOf(
            // Bech32
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
            // Bech32m
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        )
        inputs.forEach {
            val (hrp1, data1, encoding1) = Bech32.decode(it)
            val (hrp2, data2, encoding2) = Bech32.decode(it.dropLast(6), noChecksum = true)
            assertEquals(hrp1, hrp2)
            assertContentEquals(data1, data2)
            assertEquals(encoding2, Bech32.Encoding.Beck32WithoutChecksum)
            assertEquals(it.lowercase(), Bech32.encode(hrp1, data1, encoding1))
            assertEquals(it.lowercase().dropLast(6), Bech32.encode(hrp2, data2, encoding2))
        }
    }

    @Test
    fun `invalid checksums`() {
        val inputs = listOf(
            // Bech32
            " 1nwldj5",
            "\u007f1axkwrx",
            "\u00801eym55h",
            "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
            "pzry9x0s0muk",
            "1pzry9x0s0muk",
            "x1b4n0q5v",
            "li1dgmt3",
            "de1lg7wt\u00ff",
            "A1G7SGD8",
            "10a06t8",
            "1qzzfhee",
            // Bech32m
            "\u00201xj0phk",
            "\u007F1g6xzxy",
            "\u00801vctc34",
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "qyrz8wqd2c9m",
            "1qyrz8wqd2c9m",
            "y1b0jsk6g",
            "lt1igcx5c0",
            "in1muywd",
            "mm1crxm3i",
            "au1s5cgom",
            "M1VUXWEZ",
            "16plkw9",
            "1p2gdwpf"
        )
        inputs.forEach {
            assertFails {
                Bech32.decodeWitnessAddress(it)
            }
        }
    }

    @Test
    fun `decode addresses`() {
        val inputs = listOf(
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" to "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" to "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y" to "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
            "BC1SW50QGDZ25J" to "6002751e",
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs" to "5210751e76e8199196d454941c45d1b3a323",
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" to "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c" to "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0" to "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        inputs.forEach {
            val (_, _, bin1) = Bech32.decodeWitnessAddress(it.first)
            assertEquals(it.second.substring(4), Hex.encode(bin1))
        }
    }

    @Test
    fun `create addresses`() {
        assertEquals(Bech32.encodeWitnessAddress("bc", 0, Hex.decode("751e76e8199196d454941c45d1b3a323f1433bd6")), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".lowercase())
        assertEquals(Bech32.encodeWitnessAddress("bc", 1, Hex.decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")), "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
        assertEquals(Bech32.encodeWitnessAddress("tb", 0, Hex.decode("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")), "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        assertEquals(Bech32.encodeWitnessAddress("tb", 0, Hex.decode("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433")), "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy")
        assertEquals(Bech32.encodeWitnessAddress("tb", 1, Hex.decode("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433")), "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c")
    }

    @Test
    fun `reject invalid addresses`() {
        val addresses = listOf(
            // Bech32
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            "bc1rw5uspcuh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            "bc1gmk9yu",
            // Bech32m
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            "bc1pw5dgrnzv",
            "bc1pw5dgrnzv",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        )
        addresses.forEach {
            assertFails {
                Bech32.decodeWitnessAddress(it)
            }
        }
    }

    @Test
    fun `encode and decode arbitrary data`() {
        val bin = listOf(
            Hex.decode("00"),
            Hex.decode("ff"),
            Hex.decode("0102030405"),
            Hex.decode("01ff02a12abc"),
            Hex.decode("20000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
            Hex.decode("28751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")
        )
        bin.forEach {
            val encoded = Bech32.encodeBytes("hrp", it, Bech32.Encoding.Beck32WithoutChecksum)
            val (hrp, decoded, encoding) = Bech32.decodeBytes(encoded, noChecksum = true)
            assertEquals("hrp", hrp)
            assertEquals(Bech32.Encoding.Beck32WithoutChecksum, encoding)
            assertContentEquals(it, decoded)
        }
    }
}