package fr.acinq.bitcoin.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*


private typealias Init<C> = (CValuesRef<C>?) -> Unit
private typealias Update<C> = (CValuesRef<C>?, CValuesRef<*>?, CC_LONG) -> Unit
private typealias Final<C> = (CValuesRef<UByteVar>?, CValuesRef<C>?) -> Unit

@OptIn(ExperimentalUnsignedTypes::class)
internal class DigestIos<C : CVariable>(
    private val algorithmName: String,
    private val digestSize: Int,
    private val init: Init<C>,
    private val update: Update<C>,
    private val final: Final<C>,
    private val allocContext: () -> C
) : Digest {
    override fun getAlgorithmName(): String = algorithmName
    override fun getDigestSize(): Int = digestSize

    private var ctx: C? = allocContext().also { init(it.ptr) }

    override fun update(input: Byte) {
        update(byteArrayOf(input), 0, 1)
    }

    override fun update(input: ByteArray, inputOffset: Int, len: Int) {
        if (len == 0) return
        require(inputOffset >= 0 && len >= 0)
        require(inputOffset + len <= input.size) { "inputOffset + len > input.size" }
        val c = ctx ?: error("Digest closed (doFinal has been called). Call reset to restart a new one.")
        input.usePinned {
            update(c.ptr, it.addressOf(inputOffset), len.toUInt())
        }
    }

    override fun doFinal(out: ByteArray, outOffset: Int): Int {
        require(outOffset >= 0)
        require(out.size - outOffset >= digestSize) { "Output array is too small (need $digestSize bytes)" }
        val c = ctx ?: error("Digest closed (doFinal has been called). Call reset to restart a new one.")
        out.asUByteArray().usePinned {
            final(it.addressOf(outOffset), c.ptr)
        }
        nativeHeap.free(c)
        ctx = null
        return digestSize
    }

    override fun reset() {
        ctx?.let { nativeHeap.free(it) }
        ctx = allocContext().also { init(it.ptr) }
    }

}

internal actual fun Sha1(): Digest =
    DigestIos("SHA-1", CC_SHA1_DIGEST_LENGTH, ::CC_SHA1_Init, ::CC_SHA1_Update, ::CC_SHA1_Final) { nativeHeap.alloc() }

internal actual fun Sha256(): Digest =
    DigestIos("SHA-256", CC_SHA256_DIGEST_LENGTH, ::CC_SHA256_Init, ::CC_SHA256_Update, ::CC_SHA256_Final) { nativeHeap.alloc() }

internal actual fun Sha512(): Digest =
    DigestIos("SHA-512", CC_SHA512_DIGEST_LENGTH, ::CC_SHA512_Init, ::CC_SHA512_Update, ::CC_SHA512_Final) { nativeHeap.alloc() }
