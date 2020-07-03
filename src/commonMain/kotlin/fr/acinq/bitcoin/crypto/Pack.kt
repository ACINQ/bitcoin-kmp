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

import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.bitcoin.io.readNBytes
import kotlin.jvm.JvmStatic

public object Pack {
    @JvmStatic
    public fun int16BE(bs: ByteArray, off: Int = 0): Short {
        require(bs.size - off >= Short.SIZE_BYTES)
        var n: Int = bs[off].toInt() and 0xff shl 8
        n = n or (bs[off + 1].toInt() and 0xff)
        return n.toShort()
    }

    @JvmStatic
    public fun int16BE(input: Input): Short = int16BE(input.readNBytes(Short.SIZE_BYTES))

    @JvmStatic
    public fun int16LE(bs: ByteArray, off: Int = 0): Short {
        require(bs.size - off >= Short.SIZE_BYTES)
        var n: Int = bs[off].toInt() and 0xff
        n = n or (bs[off + 1].toInt() and 0xff).shl(8)
        return n.toShort()
    }

    @JvmStatic
    public fun int16LE(input: Input): Short = int16LE(input.readNBytes(Short.SIZE_BYTES))

    @JvmStatic
    public fun writeInt16BE(n: Short, bs: ByteArray, off: Int = 0) {
        require(bs.size - off >= Short.SIZE_BYTES)
        bs[off] = (n.toInt() ushr 8).toByte()
        bs[off + 1] = n.toByte()
    }

    @JvmStatic
    public fun writeInt16BE(n: Short): ByteArray = ByteArray(Short.SIZE_BYTES).also { writeInt16BE(n, it) }

    @JvmStatic
    public fun writeInt16BE(n: Short, output: Output) { output.write(writeInt16BE(n)) }

    @JvmStatic
    public fun writeInt16LE(n: Short, bs: ByteArray, off: Int = 0) {
        require(bs.size - off >= Short.SIZE_BYTES)
        bs[off] = n.toByte()
        bs[off + 1] = (n.toInt() ushr 8).toByte()
    }

    @JvmStatic
    public fun writeInt16LE(n: Short): ByteArray = ByteArray(Short.SIZE_BYTES).also { writeInt16LE(n, it) }

    @JvmStatic
    public fun writeInt16LE(n: Short, output: Output) { output.write(writeInt16LE(n)) }

    @JvmStatic
    public fun int32BE(bs: ByteArray, off: Int = 0): Int {
        require(bs.size - off >= Int.SIZE_BYTES)
        var n: Int = bs[off].toInt() shl 24
        n = n or (bs[off + 1].toInt() and 0xff).shl(16)
        n = n or (bs[off + 2].toInt() and 0xff).shl(8)
        n = n or (bs[off + 3].toInt() and 0xff)
        return n
    }

    @JvmStatic
    public fun int32BE(input: Input): Int = int32BE(input.readNBytes(Int.SIZE_BYTES))

    @JvmStatic
    public fun int32LE(bs: ByteArray, off: Int = 0): Int {
        require(bs.size - off >= Int.SIZE_BYTES)
        var n: Int = bs[off].toInt() and 0xff
        n = n or (bs[off + 1].toInt() and 0xff).shl(8)
        n = n or (bs[off + 2].toInt() and 0xff).shl(16)
        n = n or bs[off + 3].toInt().shl(24)
        return n
    }

    @JvmStatic
    public fun int32LE(input: Input): Int = int32LE(input.readNBytes(Int.SIZE_BYTES))

    @JvmStatic
    public fun writeInt32BE(n: Int, bs: ByteArray, off: Int = 0) {
        require(bs.size - off >= Int.SIZE_BYTES)
        bs[off] = (n ushr 24).toByte()
        bs[off + 1] = (n ushr 16).toByte()
        bs[off + 2] = (n ushr 8).toByte()
        bs[off + 3] = n.toByte()
    }

    @JvmStatic
    public fun writeInt32BE(n: Int): ByteArray = ByteArray(Int.SIZE_BYTES).also { writeInt32BE(n, it) }

    @JvmStatic
    public fun writeInt32BE(n: Int, output: Output) { output.write(writeInt32BE(n)) }

    @JvmStatic
    public fun writeInt32LE(n: Int, bs: ByteArray, off: Int = 0) {
        require(bs.size - off >= Int.SIZE_BYTES)
        bs[off] = n.toByte()
        bs[off + 1] = (n ushr 8).toByte()
        bs[off + 2] = (n ushr 16).toByte()
        bs[off + 3] = (n ushr 24).toByte()
    }

    @JvmStatic
    public fun writeInt32LE(n: Int): ByteArray = ByteArray(Int.SIZE_BYTES).also { writeInt32LE(n, it) }

    @JvmStatic
    public fun writeInt32LE(n: Int, output: Output) { output.write(writeInt32LE(n)) }

    @JvmStatic
    public fun int64BE(bs: ByteArray, off: Int = 0): Long {
        require(bs.size - off >= Long.SIZE_BYTES)
        val hi = int32BE(bs, off)
        val lo = int32BE(bs, off + 4)
        return (hi.toLong() and 0xffffffffL) shl 32 or (lo.toLong() and 0xffffffffL)
    }

    @JvmStatic
    public fun int64BE(input: Input): Long = int64BE(input.readNBytes(Long.SIZE_BYTES))

    @JvmStatic
    public fun int64LE(bs: ByteArray, off: Int = 0): Long {
        require(bs.size - off >= Long.SIZE_BYTES)
        val lo = int32LE(bs, off)
        val hi = int32LE(bs, off + 4)
        return (hi.toLong() and 0xffffffffL) shl 32 or (lo.toLong() and 0xffffffffL)
    }

    @JvmStatic
    public fun int64LE(input: Input): Long = int64LE(input.readNBytes(Long.SIZE_BYTES))

    @JvmStatic
    public fun writeInt64BE(n: Long, bs: ByteArray, off: Int = 0) {
        require(bs.size - off >= Long.SIZE_BYTES)
        writeInt32BE((n ushr 32).toInt(), bs, off)
        writeInt32BE((n and 0xffffffffL).toInt(), bs, off + 4)
    }

    @JvmStatic
    public fun writeInt64BE(n: Long): ByteArray = ByteArray(Long.SIZE_BYTES).also { writeInt64BE(n, it) }

    @JvmStatic
    public fun writeInt64BE(n: Long, output: Output) { output.write(writeInt64BE(n)) }

    @JvmStatic
    public fun writeInt64LE(n: Long, bs: ByteArray, off: Int = 0) {
        require(bs.size - off >= Long.SIZE_BYTES)
        writeInt32LE((n and 0xffffffffL).toInt(), bs, off)
        writeInt32LE((n ushr 32).toInt(), bs, off + 4)
    }

    @JvmStatic
    public fun writeInt64LE(n: Long): ByteArray = ByteArray(Long.SIZE_BYTES).also { writeInt64LE(n, it) }

    @JvmStatic
    public fun writeInt64LE(n: Long, output: Output) { output.write(writeInt64LE(n)) }
}
