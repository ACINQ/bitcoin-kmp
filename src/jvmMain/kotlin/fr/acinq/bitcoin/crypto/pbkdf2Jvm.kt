package fr.acinq.bitcoin.crypto

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec


public actual object Pbkdf2 {

    @JvmStatic
    public actual fun withHmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
            .generateSecret(
                PBEKeySpec(
                    CharArray(password.size) { password[it].toChar() },
                    salt,
                    count,
                    dkLen * 8
                )
            )
            .encoded

}
