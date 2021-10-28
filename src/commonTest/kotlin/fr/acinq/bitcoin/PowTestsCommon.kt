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

class PowTestsCommon {
    @Test
    fun `calculate next work required`() {
        val header = BlockHeader(version = 2, hashPreviousBlock = ByteVector32.Zeroes, hashMerkleRoot = ByteVector32.Zeroes, time = 0L, bits = 0L, nonce = 0L)
        assertEquals(0x1d00d86aL, BlockHeader.calculateNextWorkRequired(header.copy(time = 1262152739, bits = 0x1d00ffff), 1261130161))
        assertEquals(0x1d00ffffL, BlockHeader.calculateNextWorkRequired(header.copy(time = 1233061996, bits = 0x1d00ffff), 1231006505))
        assertEquals(0x1c0168fdL, BlockHeader.calculateNextWorkRequired(header.copy(time = 1279297671, bits = 0x1c05a3f4), 1279008237))
    }
}