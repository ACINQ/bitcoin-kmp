package fr.acinq.bitcoin.crypto

import java.nio.charset.StandardCharsets
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec


public actual object Pbkdf2 {

    @JvmStatic
    public actual fun withHmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray {
        require(password.isNotEmpty()) { "password must not be empty" }
        require(salt.isNotEmpty()) { "salt must not be empty" }

        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
            .generateSecret(
                PBEKeySpec(
                    password.toString(StandardCharsets.UTF_8).toCharArray(),
                    salt,
                    count,
                    dkLen * 8
                )
            )
            .encoded
    }

}
