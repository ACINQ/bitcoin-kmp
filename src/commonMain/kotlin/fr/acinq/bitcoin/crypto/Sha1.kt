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

public class Sha1 : Digest {
    private var H1 = 0
    private var H2 = 0
    private var H3 = 0
    private var H4 = 0
    private var H5 = 0

    private val X = IntArray(80)
    private var xOff = 0

    private val xBuf = ByteArray(4)
    private var xBufOff = 0

    private var byteCount: Long = 0

    /**
     * Standard constructor
     */
    init {
        reset()
    }

    override fun getAlgorithmName(): String {
        return "SHA-1"
    }

    override fun getDigestSize(): Int {
        return DIGEST_LENGTH
    }

    override fun update(input: Byte) {
        xBuf[xBufOff++] = input
        if (xBufOff == xBuf.size) {
            processWord(xBuf, 0)
            xBufOff = 0
        }
        byteCount++
    }

    override fun update(input: ByteArray, inputOffset: Int, len: Int) {
        val len1 = kotlin.math.max(0, len)

        //
        // fill the current word
        //
        var i = 0
        if (xBufOff != 0) {
            while (i < len1) {
                xBuf[xBufOff++] = input[inputOffset + i++]
                if (xBufOff == 4) {
                    processWord(xBuf, 0)
                    xBufOff = 0
                    break
                }
            }
        }

        //
        // process whole words.
        //
        val limit = (len1 - i and 3.inv()) + i
        while (i < limit) {
            processWord(input, inputOffset + i)
            i += 4
        }

        //
        // load in the remainder.
        //
        while (i < len1) {
            xBuf[xBufOff++] = input[inputOffset + i++]
        }
        byteCount += len1.toLong()
    }

    private fun processWord(`in`: ByteArray, inOff: Int) {
        // Note: Inlined for performance
//        X[xOff] = Pack.bigEndianToInt(in, inOff);
        var n: Int = (`in`[inOff].toInt() and 0xff) shl 24
        n = n or ((`in`[inOff + 1].toInt() and 0xff) shl 16)
        n = n or ((`in`[inOff + 2].toInt() and 0xff) shl 8)
        n = n or ((`in`[inOff + 3].toInt() and 0xff))
        X[xOff] = n
        if (++xOff == 16) {
            processBlock()
        }
    }

    protected fun processLength(bitLength: Long) {
        if (xOff > 14) {
            processBlock()
        }
        X[14] = (bitLength ushr 32).toInt()
        X[15] = bitLength.toInt()
    }

    override fun doFinal(out: ByteArray, outOffset: Int): Int {
        finish()
        Pack.writeInt32BE(H1, out, outOffset)
        Pack.writeInt32BE(H2, out, outOffset + 4)
        Pack.writeInt32BE(H3, out, outOffset + 8)
        Pack.writeInt32BE(H4, out, outOffset + 12)
        Pack.writeInt32BE(H5, out, outOffset + 16)
        reset()
        return DIGEST_LENGTH
    }

    public fun finish() {
        val bitLength: Long = byteCount shl 3

        //
        // add the pad bytes.
        //
        update(128.toByte())
        while (xBufOff != 0) {
            update(0.toByte())
        }
        processLength(bitLength)
        processBlock()
    }

    /**
     * reset the chaining variables
     */
    override fun reset() {
        byteCount = 0

        xBufOff = 0
        for (i in xBuf.indices) {
            xBuf[i] = 0
        }

        H1 = 0x67452301
        H2 = -0x10325477
        H3 = -0x67452302
        H4 = 0x10325476
        H5 = -0x3c2d1e10
        xOff = 0
        for (i in X.indices) {
            X[i] = 0
        }
    }

    protected fun processBlock() {
        //
        // expand 16 word block into 80 word block.
        //
        for (i in 16..79) {
            val t = X[i - 3] xor X[i - 8] xor X[i - 14] xor X[i - 16]
            X[i] = (t shl 1) or (t ushr 31)
        }

        //
        // set up working variables.
        //
        var A = H1
        var B: Int = H2
        var C: Int = H3
        var D: Int = H4
        var E: Int = H5

        //
        // round 1
        //
        var idx = 0
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            E += ((A shl 5) or (A ushr 27)) + f(B, C, D) + X[idx++] + Y1
            B = (B shl 30) or (B ushr 2)
            D += ((E shl 5) or (E ushr 27)) + f(A, B, C) + X[idx++] + Y1
            A = (A shl 30) or (A ushr 2)
            C += ((D shl 5) or (D ushr 27)) + f(E, A, B) + X[idx++] + Y1
            E = (E shl 30) or (E ushr 2)
            B += ((C shl 5) or (C ushr 27)) + f(D, E, A) + X[idx++] + Y1
            D = (D shl 30) or (D ushr 2)
            A += ((B shl 5) or (B ushr 27)) + f(C, D, E) + X[idx++] + Y1
            C = (C shl 30) or (C ushr 2)
        }

        //
        // round 2
        //
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            E += ((A shl 5) or (A ushr 27)) + h(B, C, D) + X[idx++] + Y2
            B = (B shl 30) or (B ushr 2)
            D += ((E shl 5) or (E ushr 27)) + h(A, B, C) + X[idx++] + Y2
            A = (A shl 30) or (A ushr 2)
            C += ((D shl 5) or (D ushr 27)) + h(E, A, B) + X[idx++] + Y2
            E = (E shl 30) or (E ushr 2)
            B += ((C shl 5) or (C ushr 27)) + h(D, E, A) + X[idx++] + Y2
            D = (D shl 30) or (D ushr 2)
            A += ((B shl 5) or (B ushr 27)) + h(C, D, E) + X[idx++] + Y2
            C = (C shl 30) or (C ushr 2)
        }

        //
        // round 3
        //
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            E += ((A shl 5) or (A ushr 27)) + g(B, C, D) + X[idx++] + Y3
            B = (B shl 30) or (B ushr 2)
            D += ((E shl 5) or (E ushr 27)) + g(A, B, C) + X[idx++] + Y3
            A = (A shl 30) or (A ushr 2)
            C += ((D shl 5) or (D ushr 27)) + g(E, A, B) + X[idx++] + Y3
            E = (E shl 30) or (E ushr 2)
            B += ((C shl 5) or (C ushr 27)) + g(D, E, A) + X[idx++] + Y3
            D = (D shl 30) or (D ushr 2)
            A += ((B shl 5) or (B ushr 27)) + g(C, D, E) + X[idx++] + Y3
            C = (C shl 30) or (C ushr 2)
        }

        //
        // round 4
        //
        for (j in 0..3) {
            // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            E += ((A shl 5) or (A ushr 27)) + h(B, C, D) + X[idx++] + Y4
            B = (B shl 30) or (B ushr 2)
            D += ((E shl 5) or (E ushr 27)) + h(A, B, C) + X[idx++] + Y4
            A = (A shl 30) or (A ushr 2)
            C += ((D shl 5) or (D ushr 27)) + h(E, A, B) + X[idx++] + Y4
            E = (E shl 30) or (E ushr 2)
            B += ((C shl 5) or (C ushr 27)) + h(D, E, A) + X[idx++] + Y4
            D = (D shl 30) or (D ushr 2)
            A += ((B shl 5) or (B ushr 27)) + h(C, D, E) + X[idx++] + Y4
            C = (C shl 30) or (C ushr 2)
        }
        H1 += A
        H2 += B
        H3 += C
        H4 += D
        H5 += E

        //
        // reset start of the buffer.
        //
        xOff = 0
        for (i in 0..15) {
            X[i] = 0
        }
    }

    public companion object {
        private val DIGEST_LENGTH = 20

        public fun hash(input: ByteArray, offset: Int, len: Int): ByteArray {
            val sha1 = Sha1()
            sha1.update(input, offset, len)
            val output = ByteArray(DIGEST_LENGTH)
            sha1.doFinal(output, 0)
            return output
        }

        public fun hash(input: ByteArray): ByteArray = hash(input, 0, input.size)

        //
        // Additive constants
        //
        private val Y1 = 0x5a827999
        private val Y2 = 0x6ed9eba1
        private val Y3 = -0x70e44324
        private val Y4 = -0x359d3e2a

        private fun f(u: Int, v: Int, w: Int): Int {
            return u and v or (u.inv() and w)
        }

        private fun h(u: Int, v: Int, w: Int): Int {
            return u xor v xor w
        }

        private fun g(u: Int, v: Int, w: Int): Int {
            return u and v or (u and w) or (v and w)
        }
    }
}
