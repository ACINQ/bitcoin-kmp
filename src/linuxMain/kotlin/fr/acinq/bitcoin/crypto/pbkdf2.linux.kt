package fr.acinq.bitcoin.crypto

public actual object Pbkdf2 {
    public actual fun withHmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray =
        Pbkdf2Native.withHmacSha512(password, salt, count, dkLen)
}
