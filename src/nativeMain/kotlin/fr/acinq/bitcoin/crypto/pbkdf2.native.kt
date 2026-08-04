package fr.acinq.bitcoin.crypto

import kotlin.experimental.xor

public object Pbkdf2Native {

    private interface Prf {
        fun outputLen(): Int
        fun process(input: ByteArray): ByteArray
    }

    private class Hmac512(password: ByteArray) : Prf {
        private val digest: Digest = Digest.sha512()

        // The padded keys only depend on the password, which is the same for every iteration: we derive them once
        // here instead of recomputing them on each call to process(), which would dominate the cost of the HMAC.
        private val ipad: ByteArray
        private val opad: ByteArray

        init {
            val key = if (password.size > BlockSize) digest.hash(password) else password
            ipad = ByteArray(BlockSize) { if (it < key.size) key[it] xor 0x36 else 0x36 }
            opad = ByteArray(BlockSize) { if (it < key.size) key[it] xor 0x5c else 0x5c }
        }

        override fun outputLen(): Int = 64

        override fun process(input: ByteArray): ByteArray = hash(opad, hash(ipad, input))

        private fun hash(pad: ByteArray, data: ByteArray): ByteArray {
            digest.reset()
            digest.update(pad, 0, pad.size)
            digest.update(data, 0, data.size)
            val output = ByteArray(digest.getDigestSize())
            digest.doFinal(output, 0)
            return output
        }

        companion object {
            const val BlockSize: Int = 128
        }
    }

    private fun generate(salt: ByteArray, count: Int, dkLen: Int, prf: Prf): ByteArray {
        require(count >= 1) { "iteration count must be greater than 0" }
        require(dkLen >= 1) { "derived key length must be greater than 0" }
        val hLen = prf.outputLen()
        // Number of blocks, i.e. ceil(dkLen / hLen), computed without overflowing and without the rounding errors
        // that a Float division introduces for large values of dkLen.
        val l = dkLen / hLen + if (dkLen % hLen == 0) 0 else 1
        val r = dkLen - (l - 1) * hLen

        fun xor(a: ByteArray, b: ByteArray) {
            require(a.size == b.size)
            for (i in a.indices) {
                a[i] = a[i] xor b[i]
            }
        }

        fun f(index: Int): ByteArray {
            var u = prf.process(salt + Pack.writeInt32BE(index))
            val output = u.copyOf()
            for (i in 1 until count) {
                u = prf.process(u)
                xor(output, u)
            }
            return output
        }

        // DK = T_1 || T_2 || ... || T_l, where the last block is truncated to r bytes (see RFC 2898 section 5.2).
        val t = ByteArray(dkLen)
        for (i in 1..l) {
            f(i).copyInto(t, destinationOffset = (i - 1) * hLen, startIndex = 0, endIndex = if (i == l) r else hLen)
        }
        return t
    }

    public fun withHmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray {
        require(password.isNotEmpty()) { "password must not be empty" }
        require(salt.isNotEmpty()) { "password must not be empty" }
        require(password.all { it >= 0 }) { "password must not contain non-ascii characters" }

        return generate(salt, count, dkLen, Hmac512(password))
    }
}
