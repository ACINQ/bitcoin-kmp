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

import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

open class ByteVector(internal val bytes: ByteArray, internal val offset: Int, protected val size: Int) {
    constructor(bytes: ByteArray) : this(bytes, 0, bytes.size)
    constructor(input: String) : this(Hex.decode(input))

    init {
        require(offset >= 0)
        require(size >= 0)
        require(offset + size <= bytes.size)
    }

    fun size() = size

    fun isEmpty() = size == 0

    operator fun get(i: Int): Byte = bytes[offset + i]

    fun take(n: Int): ByteVector {
        return ByteVector(bytes, offset, n)
    }

    fun drop(n: Int): ByteVector {
        return ByteVector(bytes, offset + n, size - n)
    }

    fun slice(from: Int, to: Int) = drop(from).take(to - from)

    open fun update(i: Int, b: Byte): ByteVector {
        val newbytes = toByteArray()
        newbytes[i] = b
        return ByteVector(newbytes)
    }

    fun takeRight(n: Int) = drop(size - n)

    fun dropRight(n: Int) = take(size - n)

    fun append(value: Byte): ByteVector {
        return ByteVector(toByteArray() + value)
    }

    fun append(other: ByteArray): ByteVector {
        return ByteVector(toByteArray() + other)
    }

    fun append(other: ByteVector): ByteVector = append(other.toByteArray())

    open fun reversed() = ByteVector(toByteArray().reversedArray())

    fun contentEquals(input: ByteArray, inputOffset: Int, inputSize: Int): Boolean {
        if (size != inputSize) return false
        for (i in 0 until size) {
            if (bytes[offset + i] != input[inputOffset + i]) return false
        }
        return true
    }

    fun contentEquals(input: ByteArray) = contentEquals(input, 0, input.size)

    fun sha256() : ByteVector32 {
        return ByteVector32(Crypto.sha256(bytes, offset, size))
    }

    fun ripemd160() : ByteVector {
        return ByteVector(Crypto.ripemd160(bytes, offset, size))
    }

    fun toByteArray() = bytes.copyOfRange(offset, offset + size)

    fun toHex() = Hex.encode(bytes, offset, size)

    override fun toString(): String = toHex()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ByteVector) return false
        return contentEquals(other.bytes, other.offset, other.size)
    }

    override fun hashCode(): Int {
        var result = 1
        for (index in offset until (offset + size)) {
            result = 31 * result + bytes[index]
        }
        return result
    }

    companion object {
        @JvmField
        val empty = ByteVector(ByteArray(0))
    }
}


class ByteVector32(bytes: ByteArray, offset: Int) : ByteVector(bytes, offset, 32) {
    constructor(bytes: ByteArray) : this(bytes, 0)
    constructor(input: String) : this(Hex.decode(input), 0)
    constructor(input: ByteVector) : this(input.bytes, input.offset)

    override fun update(i: Int, b: Byte): ByteVector32 {
        val newbytes = toByteArray()
        newbytes[i] = b
        return ByteVector32(newbytes)
    }

    override fun reversed() = ByteVector32(super.toByteArray().reversedArray())

    companion object {
        @JvmField
        val Zeroes = ByteVector32("0000000000000000000000000000000000000000000000000000000000000000")

        @JvmField
        val One = ByteVector32("0100000000000000000000000000000000000000000000000000000000000000")

        @JvmStatic
        fun fromValidHex(input: String) = ByteVector32(input)
    }
}

class ByteVector64(bytes: ByteArray, offset: Int) : ByteVector(bytes, offset, 64) {
    constructor(bytes: ByteArray) : this(bytes, 0)
    constructor(input: String) : this(Hex.decode(input), 0)

    init {
        require(offset >= 0 && offset < bytes.size)
        require(bytes.size - offset == 64) { "ByteVector64 must contain 64 bytes, not ${bytes.size - offset}" }
    }

    companion object {
        @JvmField
        val Zeroes = ByteVector64("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

        @JvmStatic
        fun fromValidHex(input: String) = ByteVector64(input)
    }
}

fun ByteArray.byteVector() = ByteVector(this)

fun ByteArray.byteVector32() = ByteVector32(this)

fun ByteArray.byteVector64() = ByteVector64(this)