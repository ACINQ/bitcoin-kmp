package fr.acinq.bitcoin.crypto

import fr.acinq.bitcoin.Hex
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HMacTestsJvm {
    @Test
    fun `hmac512`() {
        val data = Hex.decode("0x000102030405060708090a0b0c0d0e0f")
        val key = Hex.decode("0x426974636f696e2073656564")
        val mac = Crypto.hmac512(key, data)
        assertEquals(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            Hex.encode(mac)
        )
    }
}