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

import fr.acinq.bitcoin.Hex
import kotlin.test.Test
import kotlin.test.assertTrue

@OptIn(ExperimentalStdlibApi::class)
class Sha1TestsCommon {
    val testVectors = arrayOf(
        "" to "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "abc" to "a9993e364706816aba3e25717850c26c9cd0d89d"//,
        //"a".repeat(1_000_000) to "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    )

    @Test
    fun `reference tests`() {
        testVectors.forEach { (input, expected) ->
            run {
                val digest = Sha1()
                val result = ByteArray(20)
                val bin = input.encodeToByteArray()
                digest.update(bin, 0, bin.size)
                digest.doFinal(result, 0)
                assertTrue { result.contentEquals(Hex.decode(expected)) }
            }
        }
    }
}