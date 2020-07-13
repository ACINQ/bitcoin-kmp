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

package fr.acinq.bitcoin.crypto

import fr.acinq.bitcoin.Crypto
import fr.acinq.secp256k1.Hex
import org.junit.Test
import kotlin.test.assertEquals

class HMacTestsJvm {
    @Test
    fun `hmac512`() {
        val data = Hex.decode("0x000102030405060708090a0b0c0d0e0f")
        val key = Hex.decode("0x426974636f696e2073656564")
        val mac = Crypto.hmac512(key, data)
        assertEquals(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            Hex.encode(mac)
        )
    }
}