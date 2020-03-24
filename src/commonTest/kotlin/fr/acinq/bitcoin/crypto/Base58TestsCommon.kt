package fr.acinq.bitcoin.crypto

import fr.acinq.bitcoin.Base58
import fr.acinq.bitcoin.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class Base58TestsCommon {
    @Test
    fun `basic encode-decode tests`() {
        assertEquals("JxF12TrwUP45BMd", Base58.encode("Hello World".encodeToByteArray()))
        assertEquals("1", Base58.encode(ByteArray(1)))
        assertEquals("1111111", Base58.encode(ByteArray(7)))
        assertEquals("", Base58.encode(ByteArray(0)))
     }
}