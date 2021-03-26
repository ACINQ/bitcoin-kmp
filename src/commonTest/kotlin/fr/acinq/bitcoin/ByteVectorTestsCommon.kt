package fr.acinq.bitcoin

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
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

        assertEquals("offset (16) + size (64) must be <= buffer size (64)", assertFailsWith<IllegalArgumentException> { ByteVector64(Hex.decode("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"), 16) }.message)
    }
}
