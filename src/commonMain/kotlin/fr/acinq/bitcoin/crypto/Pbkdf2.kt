package fr.acinq.bitcoin.crypto

import kotlin.experimental.xor

object Pbkdf2 {
    interface Prf {
        fun outputLen() : Int
        fun process(input: ByteArray) : ByteArray
    }

    class Hmac512(val password: ByteArray) : Prf {
        val digest = Sha512()

        override fun outputLen(): Int = 64

        override fun process(input: ByteArray): ByteArray = HMac.hmac(password, input, digest, 128)
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

        fun f(i: Int): ByteArray {
            var u = prf.process(salt + Pack.writeUint32BE(i))
            var output = u.copyOf()
            for (i in 1 until count) {
                u = prf.process(u)
                xor(output, u)
            }
            return output
        }

        var t = f(1)
        for (i in 2 until l) {
            t += f(i)
        }
        return t
    }
}