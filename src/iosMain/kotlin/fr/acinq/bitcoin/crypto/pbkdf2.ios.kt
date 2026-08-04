package fr.acinq.bitcoin.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import platform.KCoreCrypto.KCCKeyDerivationPBKDF
import platform.CoreCrypto.kCCPBKDF2
import platform.CoreCrypto.kCCPRFHmacAlgSHA512


public actual object Pbkdf2 {

    @OptIn(ExperimentalUnsignedTypes::class, ExperimentalForeignApi::class)
    public actual fun withHmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray {
        require(count >= 1) { "iteration count must be greater than 0" }
        require(dkLen >= 1) { "derived key length must be greater than 0" }
        require(password.isNotEmpty()) { "password must not be empty" }
        require(salt.isNotEmpty()) { "salt must not be empty" }
        require(password.all { it >= 0 }) { "password must not contain non-ascii characters" }
        memScoped {
            val result = ByteArray(dkLen)
            val status = KCCKeyDerivationPBKDF(
                kCCPBKDF2,
                password.refTo(0).getPointer(this),
                password.size.toULong(),
                salt.asUByteArray().refTo(0).getPointer(this),
                salt.size.toULong(),
                kCCPRFHmacAlgSHA512,
                count.toUInt(),
                result.asUByteArray().refTo(0).getPointer(this),
                dkLen.toULong()
            )
            require(status == 0) { "could not derive key with PBKDF2 (status=$status)" }
            return result
        }
    }

}
