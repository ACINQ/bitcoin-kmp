package fr.acinq.bitcoin

import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

class BtcSerializerTestsCommon {
    @Test
    fun `encode and decode compact size integers`() {
        fun varintToHex(input: ULong): String {
            val output = ByteArrayOutput()
            BtcSerializer.writeVarint(input, output)
            return Hex.encode(output.toByteArray())
        }

        assertEquals("00", varintToHex(0uL))
        assertEquals("fc", varintToHex(0xfcuL))
        assertEquals("fdfd00", varintToHex(0xfduL))
        assertEquals("fdffff", varintToHex(0xffffuL))
        assertEquals("fe00000100", varintToHex(0x10000uL))
        assertEquals("feffffffff", varintToHex(0xffffffffuL))
        assertEquals("ff0000000001000000", varintToHex(0x100000000uL))
        assertEquals("ffffffffffffffffff", varintToHex(0xffffffffffffffffuL))

        // test that we can read back what we wrote using values that are trickier to encode (2^n - 1, 2^n, 2^n + 1)
        for (i in 0..31) {
            val output = ByteArrayOutput()
            val v = (1 shl i).toULong()
            BtcSerializer.writeVarint(v - 1UL, output)
            BtcSerializer.writeVarint(v, output)
            BtcSerializer.writeVarint(v + 1UL, output)
            val input = ByteArrayInput(output.toByteArray())
            assertEquals(BtcSerializer.varint(input), v - 1UL)
            assertEquals(BtcSerializer.varint(input), v)
            assertEquals(BtcSerializer.varint(input), v + 1UL)
        }
    }
}