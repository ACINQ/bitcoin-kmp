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

package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.secp256k1.Hex
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

@OptIn(ExperimentalUnsignedTypes::class)
public class UInt256() : Comparable<UInt256> {
    private val pn = UIntArray(WIDTH)

    public constructor(rhs: UInt256) : this() {
        rhs.pn.copyInto(pn, 0)
    }

    public constructor(value: Long) : this() {
        setUInt64(value)
    }

    public constructor(value: ByteArray) : this() {
        require(value.size <= 32)
        val reversed = value.reversedArray() + ByteArray(32 - value.size)
        for (i in 0 until WIDTH) {
            pn[i] = Pack.int32LE(reversed, 4 * i).toUInt()
        }
    }

    public fun setUInt64(value: Long) {
        pn[0] = (value and 0xffffffff).toUInt()
        pn[1] = (value.ushr(32) and 0xffffffff).toUInt()
        for (i in 2 until WIDTH) {
            pn[i] = 0U
        }
    }

    override fun compareTo(other: UInt256): Int {
        for (i in WIDTH - 1 downTo 0) {
            if (pn[i] < other.pn[i]) return -1
            if (pn[i] > other.pn[i]) return 1
        }
        return 0
    }

    public operator fun inc(): UInt256 {
        var i = 0
        while (i < WIDTH && ++pn[i] == 0U) i++
        return this
    }

    public operator fun unaryMinus(): UInt256 {
        val a = UInt256(this)
        for (i in a.pn.indices) {
            a.pn[i] = a.pn[i].inv()
        }
        return a.inc()
    }

    public operator fun plusAssign(other: UInt256) {
        var carry = 0L
        for (i in 0 until WIDTH) {
            val n = carry + pn[i].toLong() + other.pn[i].toLong()
            pn[i] = (n and 0xffffffffL).toUInt()
            carry = n ushr 32
        }
    }

    public operator fun minusAssign(other: UInt256) {
        plusAssign(-other)
    }

    public operator fun divAssign(other: UInt256) {
        var div = other
        val num = UInt256(this)
        for (i in pn.indices) pn[i] = 0U
        val num_bits = num.bits()
        val div_bits = div.bits()
        require(div_bits > 0) { "division by zero" }
        if (div_bits > num_bits) return
        var shift = num_bits - div_bits
        div = div shl shift
        while (shift >= 0) {
            if (num >= div) {
                num -= div
                pn[shift / 32] = pn[shift / 32] or (1U shl (shift and 31)) // set a bit of the result.
            }
            div = div shr 1 // shift back.
            shift--
        }
    }

    public operator fun timesAssign(other: UInt256) {
        val a = UInt256()
        for (j in 0 until WIDTH) {
            var carry = 0UL
            var i = 0
            while (i + j < WIDTH) {
                val n = carry + a.pn[i + j] + pn[j].toULong() * other.pn[i]
                a.pn[i + j] = (n and 0xffffffffUL).toUInt()
                carry = n shr 32
                i++
            }
        }
        a.pn.copyInto(pn, 0)
    }

    public infix fun shl(bitCount: Int): UInt256 {
        val a = UInt256()
        val k = bitCount / 32
        val shift = bitCount % 32
        for (i in 0 until WIDTH) {
            if (i + k + 1 < WIDTH && shift != 0)
                a.pn[i + k + 1] = a.pn[i + k + 1] or (pn[i].shr(32 - shift))
            if (i + k < WIDTH)
                a.pn[i + k] = a.pn[i + k] or (pn[i].shl(shift))
        }
        return a
    }

    public infix fun shr(bitCount: Int): UInt256 {
        val a = UInt256()
        val k = bitCount / 32
        val shift = bitCount % 32
        for (i in 0 until WIDTH) {
            if (i - k - 1 >= 0 && shift != 0)
                a.pn[i - k - 1] = a.pn[i - k - 1] or (pn[i] shl (32 - shift))
            if (i - k >= 0)
                a.pn[i - k] = a.pn[i - k] or (pn[i] shr shift)
        }
        return a
    }

    public fun inv(): UInt256 {
        val a = UInt256(this)
        for (i in a.pn.indices) {
            a.pn[i] = a.pn[i].inv()
        }
        return a
    }

    public fun bits(): Int {
        for (pos in WIDTH - 1 downTo 0) {
            if (pn[pos] != 0U) {
                for (nbits in 31 downTo 0) {
                    if ((pn[pos] and 1U.shl(nbits)) != 0U)
                        return 32 * pos + nbits + 1
                }
                return 32 * pos + 1
            }
        }
        return 0
    }

    public fun getLow64(): Long = pn[0].toLong() or (pn[1].toLong().shl(32))

    public fun endodeCompact(fNegative: Boolean): Long {
        var nSize = (bits() + 7) / 8
        var nCompact: Long = if (nSize <= 3) {
            getLow64() shl 8 * (3 - nSize)
        } else {
            val bn = UInt256(this) shr 8 * (nSize - 3)
            bn.getLow64()
        }
        // The 0x00800000 bit denotes the sign.
        // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
        if ((nCompact and 0x00800000L) != 0L) {
            nCompact = nCompact ushr 8
            nSize++
        }
        require((nCompact and 0x007fffffL.inv()) == 0L)
        require(nSize < 256)
        nCompact = nCompact or (nSize.toLong() shl 24)
        if (fNegative && (nCompact and 0x007fffffL.inv() != 0L)) {
            nCompact = nCompact or 0x00800000
        }
        return nCompact

    }

    public fun toDouble(): Double {
        var ret = 0.0
        var fact = 1.0
        for (i in 0 until WIDTH) {
            ret += fact * pn[i].toDouble()
            fact *= 4294967296.0
        }
        return ret
    }

    override fun toString(): String {
        val bytes = ByteArray(32)
        for (i in 0 until WIDTH) {
            Pack.writeInt32LE(pn[i].toInt(), bytes, 4 * i)
        }
        return Hex.encode(bytes.reversedArray())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as UInt256

        if (!pn.contentEquals(other.pn)) return false

        return true
    }

    override fun hashCode(): Int {
        return pn.contentHashCode()
    }

    public companion object {
        private const val WIDTH = 8

        @JvmField
        public val Zero: UInt256 = UInt256()

        @JvmStatic
        public fun decodeCompact(nCompact: Long): Triple<UInt256, Boolean, Boolean> {
            val nSize = (nCompact ushr 24).toInt()
            var nWord = nCompact and 0x007fffff
            var result = UInt256()
            if (nSize <= 3) {
                nWord = nWord ushr (8 * (3 - nSize))
                result.setUInt64(nWord)
            } else {
                result.setUInt64(nWord)
                result = result.shl(8 * (nSize - 3))
            }
            val pfNegative = nWord != 0L && (nCompact and 0x00800000L) != 0L
            val pfOverflow = nWord != 0L && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))
            return Triple(result, pfNegative, pfOverflow)
        }
    }
}