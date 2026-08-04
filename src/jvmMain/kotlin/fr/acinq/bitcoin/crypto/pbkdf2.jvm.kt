package fr.acinq.bitcoin.crypto

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec


public actual object Pbkdf2 {

    @JvmStatic
    public actual fun withHmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray {
        require(password.isNotEmpty()) { "password must not be empty" }
        require(salt.isNotEmpty()) { "salt must not be empty" }
        require(password.all { it >= 0 }) { "password must not contain non-ascii characters" }

        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
            .generateSecret(
                PBEKeySpec(
                    CharArray(password.size) { password[it].toInt().toChar() },
                    salt,
                    count,
                    dkLen * 8
                )
            )
            .encoded
    }

}
