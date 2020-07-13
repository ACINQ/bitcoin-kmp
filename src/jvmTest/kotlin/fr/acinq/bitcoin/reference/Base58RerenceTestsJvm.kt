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

package fr.acinq.bitcoin.reference


import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import fr.acinq.bitcoin.Base58
import fr.acinq.bitcoin.Base58Check
import fr.acinq.secp256k1.Hex
import kotlin.test.Test

class Base58RerenceTestsJvm {
    val mapper = jacksonObjectMapper()

    data class TestData(
        val isCompressed: Boolean?,
        val addrType: String?,
        val isPrivkey: Boolean,
        val isTesnet: Boolean
    )

    @Test
    fun `reference encode-decode test`() {
        val stream = javaClass.getResourceAsStream("/data/base58_encode_decode.json")
        val tests = mapper.readValue<Array<Array<String>>>(stream)
        tests.filter { it -> it.size == 2 }.forEach { it ->
            val hex = it[0]
            val expected = it[1]
            assert(Base58.encode(Hex.decode(hex)) == expected)
            val decoded = Base58.decode(expected)
            assert(Hex.encode(decoded) == hex)
        }
    }

    @Test
    fun `reference valid keys test`() {
        val stream = javaClass.getResourceAsStream("/data/base58_keys_valid.json")

        val tests = mapper.readValue<Array<Array<JsonNode>>>(stream)
        tests.forEach { it ->
            val base58: String = it[0].textValue()
            val (version, data) = Base58Check.decode(base58)
            val hex: String = it[1].textValue()
            val isPrivkey = it[2]["isPrivkey"].booleanValue()
            val isTestnet = it[2]["isTestnet"].booleanValue()
            if (isPrivkey) {
                val compressed = it[2]["isCompressed"].booleanValue()
                when (compressed) {
                    true -> {
                        assert(data.size == 33)
                        assert(data.last() == 1.toByte())
                        assert(Hex.encode(data.take(32).toByteArray()) == hex)
                    }
                    false -> {
                        assert(data.size == 32)
                        assert(Hex.encode(data) == hex)
                    }
                }
            } else {
                val addrType = it[2]["addrType"].textValue()
                when (Pair(addrType, isTestnet)) {
                    "pubkey" to true -> assert(version == Base58.Prefix.PubkeyAddressTestnet)
                    "pubkey" to false -> assert(version == Base58.Prefix.PubkeyAddress)
                    "script" to true -> assert(version == Base58.Prefix.ScriptAddressTestnet)
                    "script" to false -> assert(version == Base58.Prefix.ScriptAddress)
                }
                assert(Base58Check.encode(version, data) == base58)
            }
        }
    }
}