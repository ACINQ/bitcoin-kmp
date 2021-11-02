package fr.acinq.bitcoin

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith

class ByteVectorTestsCommon {

    @Test
    fun `equality between different byte vectors`() {
        assertEquals(
            ByteVector32("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
            ByteVector(Hex.decode("FFFF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0000"), 2, 32)
        )
        assertEquals(
            ByteVector("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
            ByteVector32(Hex.decode("FFFF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0000"), 2)
        )
        assertEquals(
            ByteVector64("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"),
            ByteVector(Hex.decode("0000FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FFFF"), 2, 64)
        )
        assertEquals(
            ByteVector("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"),
            ByteVector64(Hex.decode("0000FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FFFF"), 2)
        )
    }

    @Test
    fun `bad sized vectors`() {
        assertEquals("offset (0) + size (32) must be <= buffer size (8)", assertFailsWith<IllegalArgumentException> { ByteVector32("0123456789ABCDEF") }.message)
        assertEquals("offset (8) + size (32) must be <= buffer size (32)", assertFailsWith<IllegalArgumentException> { ByteVector32(Hex.decode("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"), 8) }.message)
        assertEquals("offset (0) + size (64) must be <= buffer size (16)", assertFailsWith<IllegalArgumentException> { ByteVector64("0123456789ABCDEF0123456789ABCDEF") }.message)
        assertEquals(
            "offset (16) + size (64) must be <= buffer size (64)",
            assertFailsWith<IllegalArgumentException> { ByteVector64(Hex.decode("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"), 16) }.message
        )
    }

    @Test
    fun `concat byte vectors`() {
        assertEquals(ByteVector("010203").concat(0x04).concat(0x05), ByteVector("0102030405"))
        assertEquals(ByteVector("010203").concat(ByteVector("0405")), ByteVector("0102030405"))
        assertEquals(ByteVector("010203").concat(ByteVector("0405")).concat(ByteVector("0607")), ByteVector("01020304050607"))
        assertEquals(ByteVector("010203").concat(listOf()), ByteVector("010203"))
        assertEquals(ByteVector("010203").concat(listOf(ByteVector("0405"))), ByteVector("0102030405"))
        assertEquals(ByteVector("010203").concat(listOf(ByteVector("0405"), ByteVector("06"), ByteVector("0708"))), ByteVector("0102030405060708"))
    }

    @Test
    fun `slice byte vectors`() {
        val v = ByteVector.fromHex("0102030405060708090a0b0c0d0e0f")
        val v1 = v.slice(3, 11)
        assertEquals(v1.toHex(), "0405060708090a0b")
        val v2 = v1.slice(1, 5)
        assertEquals(v2.toHex(), "05060708")
        val v3 = v.slice(4, 8)
        assertEquals(v2, v3)
        val v4 = v1.concat(v2)
        assertEquals(v4.toHex(), "0405060708090a0b05060708")
        val v5 = v4.slice(5, 10)
        assertEquals(v5.toHex(), "090a0b0506")
    }

    @Test
    fun `reverse byte vectors`() {
        val v = ByteVector.fromHex("0102030405060708090a0b0c0d0e0f")
        val v1 = v.reversed()
        assertEquals(v1.toHex(), "0f0e0d0c0b0a090807060504030201")
        val v2 = v.slice(3, 9).reversed()
        assertEquals(v2.toHex(), "090807060504")
        val v3 = v1.slice(3, 9)
        assertEquals(v3.toHex(), "0c0b0a090807")
        val v4 = v3.update(2, 0x00)
        assertEquals(v4.toHex(), "0c0b00090807")
    }

    @Test
    fun `pad byte vectors`() {
        val v = ByteVector.fromHex("0102030405060708090a0b0c0d0e0f")
        assertFails { v.padLeft(10) }
        assertFails { v.padRight(10) }
        assertEquals(v, v.padLeft(15))
        assertEquals(v, v.padRight(15))
        assertEquals(v.padLeft(16).toHex(), "000102030405060708090a0b0c0d0e0f")
        assertEquals(v.padLeft(20).toHex(), "00000000000102030405060708090a0b0c0d0e0f")
        assertEquals(v.padRight(16).toHex(), "0102030405060708090a0b0c0d0e0f00")
        assertEquals(v.padRight(20).toHex(), "0102030405060708090a0b0c0d0e0f0000000000")
    }

    @Test
    fun `logic or`() {
        val v1 = ByteVector.fromHex("010204")
        val v2 = ByteVector.fromHex("040603")
        assertEquals(v1.or(v2), v2.or(v1))
        assertEquals(v1.or(v2).toHex(), "050607")
    }

    @Test
    fun `take and drop`() {
        val v = ByteVector.fromHex("0102030405060708090a0b0c0d0e0f")
        assertEquals(v.takeRight(0), ByteVector.empty)
        assertEquals(v.take(0), ByteVector.empty)
        assertEquals(v, v.drop(0))
        assertEquals(v, v.dropRight(0))
        assertEquals(v.takeRight(7).dropRight(2).toHex(), "090a0b0c0d")
        assertEquals(v.takeRight(7).drop(2).toHex(), "0b0c0d0e0f")
        assertEquals(v.dropRight(2).takeRight(7).toHex(), "0708090a0b0c0d")
        assertEquals(v.drop(2).takeRight(7).toHex(), "090a0b0c0d0e0f")
        assertEquals(v.dropRight(7).dropRight(2).toHex(), "010203040506")
        assertEquals(v.drop(2).drop(3).toHex(), "060708090a0b0c0d0e0f")
        assertEquals(v.take(8).takeRight(2).toHex(), "0708")
        assertFails { v.take(8).takeRight(10) }
    }

    @Test
    fun `to byteVector32 and byteVector64`() {
        val v1 = ByteVector.fromHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000000")
        assertEquals(ByteVector32(v1).toHex(), "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
        assertEquals(ByteVector32(v1).reversed().toHex(), "0f0e0d0c0b0a090807060504030201000f0e0d0c0b0a09080706050403020100")
        assertEquals(ByteVector32(v1.reversed()).toHex(), "0000000f0e0d0c0b0a090807060504030201000f0e0d0c0b0a09080706050403")
        assertEquals(ByteVector32(v1).update(5, 0x00).toHex(), "000102030400060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")

        val v2 = ByteVector.fromHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00000000")
        assertEquals(ByteVector64(v2).toHex(), "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
        assertEquals(ByteVector64(v2.reversed()).toHex(), "000000000f0e0d0c0b0a090807060504030201000f0e0d0c0b0a090807060504030201000f0e0d0c0b0a090807060504030201000f0e0d0c0b0a090807060504")
        assertEquals(ByteVector64(v2).reversed().toHex(), "0f0e0d0c0b0a090807060504030201000f0e0d0c0b0a090807060504030201000f0e0d0c0b0a090807060504030201000f0e0d0c0b0a09080706050403020100")
        assertEquals(ByteVector64(v2).update(5, 0x00).toHex(), "000102030400060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
    }

}
