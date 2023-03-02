package fr.acinq.bitcoin

import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

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
        for (i in 0..63) {
            val output = ByteArrayOutput()
            val v = (1uL shl i)
            BtcSerializer.writeVarint(v - 1uL, output)
            BtcSerializer.writeVarint(v, output)
            BtcSerializer.writeVarint(v + 1uL, output)
            val input = ByteArrayInput(output.toByteArray())
            assertEquals(BtcSerializer.varint(input), v - 1uL)
            assertEquals(BtcSerializer.varint(input), v)
            assertEquals(BtcSerializer.varint(input), v + 1uL)
        }
    }

    @Test
    fun `encode and decoded OP_PUSHDATA`() {
        val script = listOf(OP_PUSHDATA(ByteArray(255) { 0x01 }))
        val encoded = Script.write(script)
        val decoded = Script.parse(encoded)
        assertEquals(script, decoded)

        fun serde(push: OP_PUSHDATA) {
            assertEquals(listOf(push), Script.parse(Script.write(listOf(push))))
        }
        listOf(
            OP_PUSHDATA(ByteArray(0x01) { 0x01 }, 0x01),
            OP_PUSHDATA(ByteArray(0x01) { 0x01 }, 0x4c), // non-minimal encoding
            OP_PUSHDATA(ByteArray(0x01) { 0x01 }, 0x4d), // non-minimal encoding
            OP_PUSHDATA(ByteArray(0x01) { 0x01 }, 0x4e), // non-minimal encoding
            OP_PUSHDATA(ByteArray(0xff) { 0x01 }, 0x4c),
            OP_PUSHDATA(ByteArray(0xff) { 0x01 }, 0x4d), // non-minimal encoding
            OP_PUSHDATA(ByteArray(0xffff) { 0x01 }, 0x4e), // non-minimal encoding
        ).forEach { serde(it) }

        listOf("04deadbeef", "4c04deadbeef", "4d0400deadbeef", "4e04000000deadbeef").forEach { // all encode "deadbeef"
            val parsed = Script.parse(it)
            assertEquals(1, parsed.size)
            assertTrue(ScriptElt.isPush(parsed.first(), 4))
        }

        // invalid pushes
        listOf(
            OP_PUSHDATA(ByteArray(32) { 0x01 }, 0x31), // opCode != size
            OP_PUSHDATA(ByteArray(0xff + 1) { 0x01 }, 0x4c), // too big
            OP_PUSHDATA(ByteArray(0xffff + 1) { 0x01 }, 0x4d), // too big
        ).forEach {
            assertFailsWith<IllegalArgumentException> { Script.write(listOf(it)) }
        }
    }
}