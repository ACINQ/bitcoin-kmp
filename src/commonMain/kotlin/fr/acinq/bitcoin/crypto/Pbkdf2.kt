/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.bitcoin.crypto

import kotlin.experimental.xor

public object Pbkdf2 {
    public interface Prf {
        public fun outputLen(): Int
        public fun process(input: ByteArray): ByteArray
    }

    public class Hmac512(public val password: ByteArray) : Prf {
        public val digest: Sha512 = Sha512()

        override fun outputLen(): Int = 64

        override fun process(input: ByteArray): ByteArray = HMac.hmac(password, input, digest, 128)
    }

    public fun generate(salt: ByteArray, count: Int, dkLen: Int, prf: Prf): ByteArray {
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