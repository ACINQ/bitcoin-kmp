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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class Bech32TestsCommon {
    @Test
    fun `valid`() {
        val inputs = listOf(
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl"
        )
        val outputs = inputs.map(Bech32::decode)
        assertEquals(outputs.size, inputs.size)
    }

    @Test
    fun `invalid`() {
        val inputs = listOf(
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
            "1qzzfhee"
        )
        inputs.forEach {
            assertFails {
                println(Bech32.decodeWitnessAddress(it))
            }
        }
    }

    @Test
    fun `decode addresses`() {
        val inputs = listOf(
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4" to "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" to "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx" to "8128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
            "BC1SW50QA3JX3S" to "9002751e",
            "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj" to "8210751e76e8199196d454941c45d1b3a323",
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy" to "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
        )
        inputs.forEach {
            val (_, _, bin1) = Bech32.decodeWitnessAddress(it.first)
            assertEquals(it.second.substring(4), Hex.encode(bin1))
        }
    }

    @Test
    fun `create addresses`() {
        assertEquals(Bech32.encodeWitnessAddress("bc", 0, Hex.decode("751e76e8199196d454941c45d1b3a323f1433bd6")), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".toLowerCase())
        assertEquals(Bech32.encodeWitnessAddress("tb", 0, Hex.decode("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")), "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        assertEquals(Bech32.encodeWitnessAddress("tb", 0, Hex.decode("000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433")), "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy")
    }

    @Test
    fun `reject invalid addresses`() {
        val addresses = listOf(
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
            "bc1gmk9yu"
        )
        addresses.forEach {
            assertFails {
                Bech32.decodeWitnessAddress(it)
            }
        }
    }
}