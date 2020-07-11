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
import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.Hex
import org.junit.Test

class KeyEncodingTestsJvm {
    val mapper = jacksonObjectMapper()

    @Test
    fun `valid keys`() {
        val stream = javaClass.getResourceAsStream("/data/key_io_valid.json")
        val tests = mapper.readValue<Array<Array<JsonNode>>>(stream)
        tests.filter { it.size == 3 }.forEach {
            var encoded: String = it[0].textValue()
            val hex: String = it[1].textValue()
            val isPrivkey = it[2]["isPrivkey"].booleanValue()
            val chain = it[2]["chain"].textValue()
            val tryCaseFlip = it[2]["tryCaseFlip"]?.booleanValue() ?: false
            if (isPrivkey) {
                val (version, data) = Base58Check.decode(encoded)
                assert(version == Base58.Prefix.SecretKey || version == Base58.Prefix.SecretKeyTestnet)
                assert(Hex.encode(data.take(32).toByteArray()) == hex)
                val isCompressed = it[2]["isCompressed"]?.booleanValue()
                isCompressed?.let {
                    when (it) {
                        false -> assert(data.size == 32)
                        true -> assert(data.size == 33 && data.last() == 1.toByte())
                    }
                }
            } else {
                when (encoded.first()) {
                    '1', 'm', 'n' -> {
                        val (version, data) = Base58Check.decode(encoded)
                        assert(version == Base58.Prefix.PubkeyAddress || version == Base58.Prefix.PubkeyAddressTestnet)
                        assert(
                            Script.parse(hex) == listOf(
                                OP_DUP,
                                OP_HASH160,
                                OP_PUSHDATA(data),
                                OP_EQUALVERIFY,
                                OP_CHECKSIG
                            )
                        )
                    }
                    '2', '3' -> {
                        val (version, data) = Base58Check.decode(encoded)
                        assert(version == Base58.Prefix.ScriptAddress || version == Base58.Prefix.ScriptAddressTestnet)
                        assert(Script.parse(hex) == listOf(OP_HASH160, OP_PUSHDATA(data), OP_EQUAL))
                    }
                    else -> {
                        if (tryCaseFlip) {
                            encoded = encoded.map { c ->
                                when (c) {
                                    in 'a'..'z' -> 'A' + (c - 'a')
                                    in 'A'..'Z' -> 'a' + (c - 'A')
                                    else -> c
                                }
                            }.joinToString("")
                        }
                        val prefix = when (chain) {
                            "main" -> "bc"
                            "test" -> "tb"
                            "regtest" -> "bcrt"
                            else -> throw IllegalArgumentException("invalid chain $chain")
                        }
                        require(encoded.startsWith(prefix, ignoreCase = true))
                        val (_, tag, program) = Bech32.decodeWitnessAddress(encoded)
                        assert(Script.parse(hex) == listOf(Script.fromSimpleValue(tag), OP_PUSHDATA(program)))
                    }
                }
            }
        }
    }

    @Test
    fun `invalid keys`() {
        val stream = javaClass.getResourceAsStream("/data/key_io_invalid.json")
        val tests = mapper.readValue<Array<Array<String>>>(stream)
        tests.forEach {
            val value = it[0]
            assert(!isValidBase58(value))
            assert(!isValidBech32(value))
        }
    }

    private fun isValidBase58(value: String): Boolean {
        return try {
            val (prefix, bin) = Base58Check.decode(value)
            when (prefix) {
                Base58.Prefix.SecretKey, Base58.Prefix.SecretKeyTestnet -> {
                    PrivateKey(bin)
                    true
                }
                Base58.Prefix.PubkeyAddress, Base58.Prefix.PubkeyAddressTestnet -> bin.size == 20
                else -> false
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun isValidBech32(value: String): Boolean {
        return try {
            val (hrp, flag, bin) = Bech32.decodeWitnessAddress(value)
            when {
                flag == 0.toByte() && (hrp == "bc" || hrp == "tb" || hrp == "bcrt") && (bin.size == 20 || bin.size == 32) -> true
                else -> false
            }
        } catch (e: Exception) {
            false
        }
    }
}