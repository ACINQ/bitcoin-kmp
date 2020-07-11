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

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertTrue

@ExperimentalStdlibApi
class Sha256Spec {
    val testVectors = arrayOf(
        "" to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "abc" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "a".repeat(1_000_000) to "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    )

    @Test
    fun `reference tests`() {
        testVectors.forEach { (input, expected) ->
            run {
                val digest = Sha256()
                val result = ByteArray(32)
                val bin = input.encodeToByteArray()
                digest.update(bin, 0, bin.size)
                digest.doFinal(result, 0)
                assertTrue { result.contentEquals(Hex.decode(expected)) }
            }
        }
    }
}