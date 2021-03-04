package fr.acinq.bitcoin.crypto

import kotlin.experimental.xor


private object Pbkdf2Linux {
    interface Prf {
        fun outputLen(): Int
        fun process(input: ByteArray): ByteArray
    }

    class Hmac512(public val password: ByteArray) : Prf {
        val digest: Digest = Digest.sha512()

        override fun outputLen(): Int = 64

        override fun process(input: ByteArray): ByteArray = digest.hmac(password, input, 128)
    }

    fun generate(salt: ByteArray, count: Int, dkLen: Int, prf: Prf): ByteArray {
        val hLen = prf.outputLen()
        val l = kotlin.math.ceil(dkLen.toFloat() / hLen).toInt()
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

        var t = f(1)
        for (i in 2 until l) {
            t += if (i == l - 1) f(i).take(r).toByteArray() else f(i)
        }
        return t
    }
}

public actual fun pbkdf2HmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray =
    Pbkdf2Linux.generate(salt, count, dkLen, Pbkdf2Linux.Hmac512(password))
