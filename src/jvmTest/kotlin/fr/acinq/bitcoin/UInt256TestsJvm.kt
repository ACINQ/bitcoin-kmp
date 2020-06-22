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

import org.junit.Test
import kotlin.test.assertEquals

class UInt256TestsJvm {
    @Test
    fun `init`() {
        val uint256 = UInt256(Hex.decode("c0b91a94a26dc9be07374c2280e43b1de54be568b2509ef3ce1ade5c9cf9e8aa"))
        assertEquals("c0b91a94a26dc9be07374c2280e43b1de54be568b2509ef3ce1ade5c9cf9e8aa", uint256.toString())
    }

    @Test
    fun `shl`() {
        val x = UInt256(Hex.decode("c0b91a94a26dc9be07374c2280e43b1de54be568b2509ef3ce1ade5c9cf9e8aa"))
        assertEquals("c0b91a94a26dc9be07374c2280e43b1de54be568b2509ef3ce1ade5c9cf9e8aa", x.shl(0).toString())
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", x.shl(256).toString())
        assertEquals("a26dc9be07374c2280e43b1de54be568b2509ef3ce1ade5c9cf9e8aa00000000", x.shl(32).toString())
        assertEquals("352944db937c0e6e984501c8763bca97cad164a13de79c35bcb939f3d1540000", x.shl(17).toString())
        assertEquals("9be07374c2280e43b1de54be568b2509ef3ce1ade5c9cf9e8aa0000000000000", x.shl(52).toString())
    }

    @Test
    fun `shr`() {
        val x = UInt256(Hex.decode("c0b91a94a26dc9be07374c2280e43b1de54be568b2509ef3ce1ade5c9cf9e8aa"))
        assertEquals("c0b91a94a26dc9be07374c2280e43b1de54be568b2509ef3ce1ade5c9cf9e8aa", x.shr(0).toString())
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", x.shr(256).toString())
        assertEquals("00000000c0b91a94a26dc9be07374c2280e43b1de54be568b2509ef3ce1ade5c", x.shr(32).toString())
        assertEquals("0000605c8d4a5136e4df039ba61140721d8ef2a5f2b459284f79e70d6f2e4e7c", x.shr(17).toString())
        assertEquals("0000000000000c0b91a94a26dc9be07374c2280e43b1de54be568b2509ef3ce1", x.shr(52).toString())
    }

    @Test
    fun `error`() {
        assertEquals(Triple(UInt256(0x12345600), false, false), UInt256.decodeCompact(0x04123456))
    }

    @Test
    fun `decodeCompact`() {
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x00123456))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x02000056))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x03000000))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x04000000))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x00923456))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x01803456))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x02800056))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x03800000))
        assertEquals(Triple(UInt256.Zero, false, false), UInt256.decodeCompact(0x04800000))
        assertEquals(Triple(UInt256(0x12), false, false), UInt256.decodeCompact(0x01123456))
        assertEquals(Triple(UInt256(0x7e), true, false), UInt256.decodeCompact(0x01fedcba))
        assertEquals(Triple(UInt256(0x1234), false, false), UInt256.decodeCompact(0x02123456))
        assertEquals(Triple(UInt256(0x123456), false, false), UInt256.decodeCompact(0x03123456))
        assertEquals(Triple(UInt256(0x12345600), false, false), UInt256.decodeCompact(0x04123456))
        assertEquals(Triple(UInt256(0x12345600), true, false), UInt256.decodeCompact(0x04923456))
        assertEquals(Triple(UInt256(Hex.decode("92340000")), false, false), UInt256.decodeCompact(0x05009234))
        assertEquals(
            Triple(
                UInt256(Hex.decode("1234560000000000000000000000000000000000000000000000000000000000")),
                false,
                false
            ), UInt256.decodeCompact(0x20123456)
        )

        /*
        assert(decodeCompact(0x02123456) == Triple(BigInteger.valueOf(0x1234), false, false))
        assert(decodeCompact(0x03123456) == Triple(BigInteger.valueOf(0x123456), false, false))
        assert(decodeCompact(0x04123456) == Triple(BigInteger.valueOf(0x12345600), false, false))
        assert(decodeCompact(0x04923456) == Triple(BigInteger.valueOf(0x12345600), true, false))
        assert(decodeCompact(0x05009234) == Triple(BigInteger(1, ByteVector("92340000").bytes), false, false))
        assert(decodeCompact(0x20123456) == Triple(BigInteger(1, ByteVector("1234560000000000000000000000000000000000000000000000000000000000").bytes), false, false))

         */
    }
}