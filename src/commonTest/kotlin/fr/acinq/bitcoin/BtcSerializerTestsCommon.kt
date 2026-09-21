package fr.acinq.bitcoin

import fr.acinq.bitcoin.BtcSerializer.Companion.MAX_SIZE
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
            val rangeCheck = v + 1uL < MAX_SIZE
            assertEquals(BtcSerializer.varint(input, rangeCheck), v - 1uL)
            assertEquals(BtcSerializer.varint(input, rangeCheck), v)
            assertEquals(BtcSerializer.varint(input, rangeCheck), v + 1uL)
        }
    }

    @Test
    fun `reject non-canonical compact size integers`() {
        // Values that could have been encoded on fewer bytes must be rejected (bitcoin core's ReadCompactSize).
        listOf(
            "fd0000", // 0 encoded on 3 bytes
            "fd0100", // 1 encoded on 3 bytes
            "fdfc00", // 252 encoded on 3 bytes
            "fe00000000", // 0 encoded on 5 bytes
            "fefcff0000", // 65532 encoded on 5 bytes
            "feffff0000", // 65535 encoded on 5 bytes
            "ff0000000000000000", // 0 encoded on 9 bytes
            "ffffffffff00000000", // 4294967295 encoded on 9 bytes
        ).forEach {
            assertFailsWith<IllegalArgumentException>("$it should be rejected") {
                BtcSerializer.varint(Hex.decode(it))
            }
        }

        // The smallest value that each encoding may carry is canonical.
        assertEquals(0xfcuL, BtcSerializer.varint(Hex.decode("fc")))
        assertEquals(0xfduL, BtcSerializer.varint(Hex.decode("fdfd00")))
        assertEquals(0x10000uL, BtcSerializer.varint(Hex.decode("fe00000100")))
        assertEquals(0x100000000uL, BtcSerializer.varint(Hex.decode("ff0000000001000000"), rangeCheck = false))
    }

    @Test
    fun `reject oversized compact size integers`() {
        assertEquals(0x02000000uL, BtcSerializer.varint(Hex.decode("fe00000002")))
        assertFailsWith<IllegalArgumentException> { BtcSerializer.varint(Hex.decode("fe01000002")) }
        assertFailsWith<IllegalArgumentException> { BtcSerializer.varint(Hex.decode("ff0000000001000000")) }
    }

    @Test
    fun `reject truncated compact size integers`() {
        listOf("", "fd", "fd00", "fe", "fe000001", "ff", "ff00000000010000").forEach {
            assertFailsWith<IllegalArgumentException>("$it should be rejected") {
                BtcSerializer.varint(Hex.decode(it))
            }
        }
    }

    @Test
    fun `reject transactions using non-canonical compact size integers`() {
        val tx = Transaction.read("020000000100000000000000000000000000000000000000000000000000000000000000010000000000ffffffff01e803000000000000015100000000")
        // The same transaction, with its input count re-encoded on 3 bytes instead of 1: bitcoin core rejects it, and
        // if we accepted it the txid we compute wouldn't be the hash of the bytes we decoded.
        val nonCanonical = "02000000fd0100" + "00000000000000000000000000000000000000000000000000000000000000010000000000ffffffff01e803000000000000015100000000"
        assertEquals(1, tx.txIn.size)
        assertFailsWith<IllegalArgumentException> { Transaction.read(nonCanonical) }
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

    @Test
    fun `reject oversized script lengths`() {
        val input = ByteArrayInput(Hex.decode("fe00000080" + "00".repeat(100)))
        assertFailsWith<IllegalArgumentException> {
            BtcSerializer.script(input)
        }
    }

    @Test
    fun `reject oversized collection counts`() {
        assertFailsWith<IllegalArgumentException> {
            BtcSerializer.readCollection(ByteArrayInput(Hex.decode("ff0100000001000000")), TxOut, 10, Protocol.PROTOCOL_VERSION)
        }
        assertFailsWith<IllegalArgumentException> {
            BtcSerializer.readCollection(ByteArrayInput(Hex.decode("fe00000080")), TxOut, 10, Protocol.PROTOCOL_VERSION)
        }
    }

    @Test
    fun `reject transaction inputs with truncated script varints`() {
        val outpointHash = "aa".repeat(32)
        val outpointIndex = "00000000"
        val scriptVarint = "ff0500000001000000"
        val fiveScriptBytes = "0102030405"
        val attackerSequence = "41414141"

        val hex = outpointHash + outpointIndex + scriptVarint + fiveScriptBytes + attackerSequence
        assertFailsWith<IllegalArgumentException> {
            TxIn.read(Hex.decode(hex))
        }
    }
}
