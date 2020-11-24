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

import fr.acinq.bitcoin.Base58
import fr.acinq.bitcoin.Base58Check
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class Base58RerenceTestsJvm {
    @Test
    fun `reference encode-decode test`() {
        val tests = TransactionTestsCommon.readData("data/base58_encode_decode.json")
        tests.jsonArray.filter { it -> it.jsonArray.size == 2 }.map { it.jsonArray }.forEach {
            val hex = it[0].jsonPrimitive.content
            val expected = it[1].jsonPrimitive.content
            assertEquals(Base58.encode(Hex.decode(hex)), expected)
            val decoded = Base58.decode(expected)
            assertEquals(Hex.encode(decoded), hex)
        }
    }

    @Test
    fun `reference valid keys test`() {
        val tests = TransactionTestsCommon.readData("data/base58_keys_valid.json")
        tests.jsonArray.forEach {
            val base58: String = it.jsonArray[0].jsonPrimitive.content
            val (version, data) = Base58Check.decode(base58)
            val hex: String = it.jsonArray[1].jsonPrimitive.content
            val isPrivkey = it.jsonArray[2].jsonObject["isPrivkey"]!!.jsonPrimitive.boolean
            val isTestnet = it.jsonArray[2].jsonObject["isTestnet"]!!.jsonPrimitive.boolean
            if (isPrivkey) {
                val compressed = it.jsonArray[2].jsonObject["isCompressed"]!!.jsonPrimitive.boolean
                when (compressed) {
                    true -> {
                        assertEquals(data.size, 33)
                        assertEquals(data.last(), 1.toByte())
                        assertEquals(Hex.encode(data.take(32).toByteArray()), hex)
                    }
                    false -> {
                        assertEquals(data.size, 32)
                        assertEquals(Hex.encode(data), hex)
                    }
                }
            } else {
                val addrType = it.jsonArray[2].jsonObject["addrType"]!!.jsonPrimitive.content
                when (Pair(addrType, isTestnet)) {
                    "pubkey" to true -> assertEquals(version, Base58.Prefix.PubkeyAddressTestnet)
                    "pubkey" to false -> assertEquals(version, Base58.Prefix.PubkeyAddress)
                    "script" to true -> assertEquals(version, Base58.Prefix.ScriptAddressTestnet)
                    "script" to false -> assertEquals(version, Base58.Prefix.ScriptAddress)
                }
                assertEquals(Base58Check.encode(version, data), base58)
            }
        }
    }
}