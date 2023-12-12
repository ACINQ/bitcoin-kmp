package fr.acinq.bitcoin.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import platform.KCoreCrypto.KCCKeyDerivationPBKDF
import platform.CoreCrypto.kCCPBKDF2
import platform.CoreCrypto.kCCPRFHmacAlgSHA256
import platform.CoreCrypto.kCCPRFHmacAlgSHA512


public actual object Pbkdf2 {

    @OptIn(ExperimentalUnsignedTypes::class, ExperimentalForeignApi::class)
    public actual fun withHmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray {
        memScoped {
            val result = ByteArray(dkLen)
            KCCKeyDerivationPBKDF(
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
            return result
        }
    }

}
