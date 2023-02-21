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

        // test that we can read back what we wrote using values that are trickier to encode (2^n  and 2^n - 1)
        var i = 1uL
        val output = ByteArrayOutput()
        while (i <= 33554432UL) {
            BtcSerializer.writeVarint(i - 1uL, output)
            BtcSerializer.writeVarint(i, output)
            i *= 2uL
        }
        i = 1uL
        val input = ByteArrayInput(output.toByteArray())
        while (i <= 33554432UL) {
            var j = BtcSerializer.varint(input)
            assertEquals(i - 1uL, j)
            j = BtcSerializer.varint(input)
            assertEquals(i, j)
            i *= 2uL
        }
    }
}