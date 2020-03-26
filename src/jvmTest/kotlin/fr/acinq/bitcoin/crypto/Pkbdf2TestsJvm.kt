package fr.acinq.bitcoin.crypto

import fr.acinq.bitcoin.Hex
import org.junit.Test

class Pkbdf2TestsJvm {
    @Test
    fun `generate`() {
        val password = Hex.decode("6162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e2061626f7574")
        val salt = Hex.decode("6d6e656d6f6e6963")
        val foo = Pbkdf2.generate(salt, 2048, 64, Pbkdf2.Hmac512(password))
        println(Hex.encode(foo))
    }
}