package fr.acinq.bitcoin.crypto

import java.security.MessageDigest


internal class DigestJvm(algorithmName: String) : Digest {

    private val digest = MessageDigest.getInstance(algorithmName)

    override fun getAlgorithmName(): String = digest.algorithm

    override fun getDigestSize(): Int = digest.digestLength

    override fun update(input: Byte): Unit = digest.update(input)

    override fun update(input: ByteArray, inputOffset: Int, len: Int): Unit = digest.update(input, inputOffset, len)

    override fun doFinal(out: ByteArray, outOffset: Int): Int = digest.digest(out, outOffset, out.size - outOffset)

    override fun reset(): Unit = digest.reset()
}

internal actual fun Sha1(): Digest = DigestJvm("SHA-1")
internal actual fun Sha256(): Digest = DigestJvm("SHA-256")
internal actual fun Sha512(): Digest = DigestJvm("SHA-512")
