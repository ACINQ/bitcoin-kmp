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

object Pack {
    fun uint16BE(bs: ByteArray, off: Int): Int {
        var n: Int = bs[off].toInt() and 0xff shl 8
        n = n or (bs[off + 1].toInt() and 0xff)
        return n
    }

    fun uint16LE(bs: ByteArray, off: Int): Int {
        var n: Int = bs[off].toInt() and 0xff
        n = n or (bs[off + 1].toInt() and 0xff).shl(8)
        return n
    }

    fun writeUint16LE(n: Int): ByteArray {
        val bs = ByteArray(2)
        writeUint16LE(n, bs, 0)
        return bs
    }

    fun writeUint16BE(n: Int): ByteArray {
        val bs = ByteArray(2)
        writeUint16BE(n, bs, 0)
        return bs
    }

    fun writeUint16LE(n: Int, bs: ByteArray, off: Int) {
        bs[off] = n.toByte()
        bs[off + 1] = (n.toInt() ushr 8).toByte()
    }

    fun writeUint16BE(n: Int, bs: ByteArray, off: Int) {
        bs[off] = (n.toInt() ushr 8).toByte()
        bs[off + 1] = n.toByte()
    }

    fun uint32BE(bs: ByteArray, off: Int): Int {
        var n: Int = bs[off].toInt() shl 24
        n = n or (bs[off + 1].toInt() and 0xff).shl(16)
        n = n or (bs[off + 2].toInt() and 0xff).shl(8)
        n = n or (bs[off + 3].toInt() and 0xff)
        return n
    }

    fun uint32BE(bs: ByteArray): Int = uint32BE(bs, 0)

    fun uint32BE(bs: ByteArray, off: Int, ns: IntArray) {
        for (i in ns.indices) {
            ns[i] = uint32BE(bs, off + 4 * i)
        }
    }

    fun writeUint32BE(n: Int): ByteArray {
        val bs = ByteArray(4)
        writeUint32BE(n, bs, 0)
        return bs
    }

    fun writeUint32BE(n: Int, bs: ByteArray, off: Int) {
        bs[off] = (n ushr 24).toByte()
        bs[off + 1] = (n ushr 16).toByte()
        bs[off + 2] = (n ushr 8).toByte()
        bs[off + 3] = n.toByte()
    }

    fun writeUint32BE(ns: IntArray): ByteArray {
        val bs = ByteArray(4 * ns.size)
        writeUint32BE(ns, bs, 0)
        return bs
    }

    fun writeUint32BE(ns: IntArray, bs: ByteArray, off: Int) {
        for (i in ns.indices) {
            writeUint32BE(ns[i], bs, off + 4 * i)
        }
    }


    fun uint32LE(bs: ByteArray, off: Int): Int {
        var n: Int = bs[off].toInt() and 0xff
        n = n or (bs[off + 1].toInt() and 0xff).shl(8)
        n = n or (bs[off + 2].toInt() and 0xff).shl(16)
        n = n or bs[off + 3].toInt().shl(24)
        return n
    }

    fun uint32LE(bs: ByteArray, off: Int, ns: IntArray) {
        for (i in ns.indices) {
            ns[i] = uint32LE(bs, off + 4 * i)
        }
    }

    fun uint32LE(bs: ByteArray, bOff: Int, ns: IntArray, nOff: Int, count: Int) {
        for (i in 0 until count) {
            ns[nOff + i] = uint32LE(bs, bOff + 4 * i)
        }
    }

    fun uint32LE(bs: ByteArray, off: Int, count: Int): IntArray {
        val ns = IntArray(count)
        for (i in ns.indices) {
            ns[i] = uint32LE(bs, off + 4 * i)
        }
        return ns
    }

    fun writeUint32LE(n: Int): ByteArray {
        val bs = ByteArray(4)
        writeUint32LE(n, bs, 0)
        return bs
    }

    fun writeUint32LE(n: Int, bs: ByteArray, off: Int) {
        bs[off] = n.toByte()
        bs[off + 1] = (n ushr 8).toByte()
        bs[off + 2] = (n ushr 16).toByte()
        bs[off + 3] = (n ushr 24).toByte()
    }

    @ExperimentalUnsignedTypes
    fun writeUint32LE(n: UInt, bs: ByteArray, off: Int) {
        bs[off] = n.toByte()
        bs[off + 1] = (n shr 8).toByte()
        bs[off + 2] = (n shr 16).toByte()
        bs[off + 3] = (n shr 24).toByte()
    }

    fun writeUint32LE(ns: IntArray): ByteArray {
        val bs = ByteArray(4 * ns.size)
        writeUint32LE(ns, bs, 0)
        return bs
    }

    fun writeUint32LE(ns: IntArray, bs: ByteArray, off: Int) {
        for (i in ns.indices) {
            writeUint32LE(ns[i], bs, off + 4 * i)
        }
    }

    fun uint64BE(bs: ByteArray, off: Int): Long {
        val hi = uint32BE(bs, off)
        val lo = uint32BE(bs, off + 4)
        return (hi.toLong() and 0xffffffffL).toLong() shl 32 or (lo.toLong() and 0xffffffffL).toLong()
    }

    fun uint64LE(bs: ByteArray, off: Int): Long {
        val lo = uint32LE(bs, off)
        val hi = uint32LE(bs, off + 4)
        return (hi.toLong() and 0xffffffffL).toLong() shl 32 or (lo.toLong() and 0xffffffffL).toLong()
    }

    fun uint64BE(bs: ByteArray, off: Int, ns: LongArray) {
        for (i in ns.indices) {
            ns[i] = uint64BE(bs, off + 8 * i)
        }
    }

    fun writeUint64BE(n: Long): ByteArray {
        val bs = ByteArray(8)
        writeUint64BE(n, bs, 0)
        return bs
    }

    fun writeUint64BE(n: Long, bs: ByteArray, off: Int) {
        writeUint32BE((n ushr 32).toInt(), bs, off)
        writeUint32BE((n and 0xffffffffL).toInt(), bs, off + 4)
    }

    fun writeUint64BE(ns: LongArray): ByteArray {
        val bs = ByteArray(8 * ns.size)
        writeUint64BE(ns, bs, 0)
        return bs
    }

    fun writeUint64BE(ns: LongArray, bs: ByteArray, off: Int) {
        for (i in ns.indices) {
            writeUint64BE(ns[i], bs, off + 8 * i)
        }
    }

    fun writeUint64LE(n: Long): ByteArray {
        val bs = ByteArray(8)
        writeUint64LE(n, bs, 0)
        return bs
    }

    fun writeUint64LE(n: Long, bs: ByteArray, off: Int) {
        writeUint32LE((n and 0xffffffffL).toInt(), bs, off)
        writeUint32LE((n ushr 32).toInt(), bs, off + 4)
    }

//    fun writeUint64LE(ns: LongArray): ByteArray {
//        val bs = ByteArray(8 * ns.size)
//        writeUint64LE(ns, bs, 0)
//        return bs
//    }
//
//    fun writeUint64LE(ns: LongArray, bs: ByteArray, off: Int) {
//        var off = off
//        for (i in ns.indices) {
//            writeUint64LE(ns[i], bs, off)
//            off += 8
//        }
//    }

//    fun writeUint64LE(ns: LongArray, nsOff: Int, nsLen: Int, bs: ByteArray, bsOff: Int) {
//        var bsOff = bsOff
//        for (i in 0 until nsLen) {
//            writeUint64LE(ns[nsOff + i], bs, bsOff)
//            bsOff += 8
//        }
//    }
//
//    fun writeUint64LE(bs: ByteArray, off: Int, ns: LongArray) {
//        var off = off
//        for (i in ns.indices) {
//            ns[i] = writeUint64LE(bs, off)
//            off += 8
//        }
//    }
//
//    fun writeUint64LE(bs: ByteArray, bsOff: Int, ns: LongArray, nsOff: Int, nsLen: Int) {
//        var bsOff = bsOff
//        for (i in 0 until nsLen) {
//            ns[nsOff + i] = writeUint64LE(bs, bsOff)
//            bsOff += 8
//        }
//    }
}
