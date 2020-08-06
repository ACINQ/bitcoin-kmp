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

import fr.acinq.secp256k1.Hex
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.experimental.or
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

@Serializable(with = ByteVector.Serializer::class)
public open class ByteVector(internal val bytes: ByteArray, internal val offset: Int, private val size: Int) {
    public constructor(bytes: ByteArray) : this(bytes, 0, bytes.size)
    public constructor(input: String) : this(Hex.decode(input))

    init {
        require(offset >= 0){ "offset ($size) must be > 0"}
        require(size >= 0){"size ($size) must be > 0"}
        require(offset + size <= bytes.size){"offset ($offset) + size ($size) must be <= buffer size (${bytes.size})"}
    }

    public fun size(): Int = size

    public fun isEmpty(): Boolean = size == 0

    public operator fun get(i: Int): Byte = bytes[offset + i]

    public fun take(n: Int): ByteVector {
        return ByteVector(bytes, offset, n)
    }

    public fun drop(n: Int): ByteVector {
        return ByteVector(bytes, offset + n, size - n)
    }

    public fun slice(from: Int, to: Int): ByteVector = drop(from).take(to - from)

    public open fun update(i: Int, b: Byte): ByteVector {
        val newbytes = toByteArray()
        newbytes[i] = b
        return ByteVector(newbytes)
    }

    public fun takeRight(n: Int): ByteVector = drop(size - n)

    public fun dropRight(n: Int): ByteVector = take(size - n)

    public fun concat(value: Byte): ByteVector {
        return ByteVector(toByteArray() + value)
    }

    public operator fun plus(other: ByteVector): ByteVector = concat(other)

    public operator fun plus(other: ByteArray): ByteVector = concat(other)

    public fun or(other: ByteVector): ByteVector {
        require(size() == other.size){ "cannot call or() on byte vectors of different sizes"}
        val data = toByteArray()
        for(i in data.indices) {
            data[i] = data[i] or other[i]
        }
        return ByteVector(data)
    }

    public fun padLeft(length: Int): ByteVector {
        require(size <= length){"byte vector larger than padding target"}
        if (length == size) return this
        return ByteVector(ByteArray(length - size) + toByteArray())
    }

    public fun padRight(length: Int): ByteVector {
        require(size <= length){"byte vector larger than padding target"}
        if (length == size) return this
        return ByteVector(toByteArray() + ByteArray(length - size))
    }

    public fun concat(other: ByteArray): ByteVector {
        return ByteVector(toByteArray() + other)
    }

    public fun concat(other: ByteVector): ByteVector = concat(other.toByteArray())

    public open fun reversed(): ByteVector = ByteVector(toByteArray().reversedArray())

    public fun contentEquals(input: ByteArray, inputOffset: Int, inputSize: Int): Boolean {
        if (size != inputSize) return false
        for (i in 0 until size) {
            if (bytes[offset + i] != input[inputOffset + i]) return false
        }
        return true
    }

    public fun contentEquals(input: ByteArray): Boolean = contentEquals(input, 0, input.size)

    public fun sha256(): ByteVector32 {
        return ByteVector32(Crypto.sha256(bytes, offset, size))
    }

    public fun ripemd160(): ByteVector {
        return ByteVector(Crypto.ripemd160(bytes, offset, size))
    }

    public fun toByteArray(): ByteArray = bytes.copyOfRange(offset, offset + size)

    public fun toHex(): String = Hex.encode(bytes, offset, size)

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

    public companion object {
        @JvmField
        public val empty: ByteVector = ByteVector(ByteArray(0))
    }

    public object Serializer: KSerializer<ByteVector> {
        override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("ByteVector", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: ByteVector) {
            encoder.encodeString(value.toHex())
        }

        override fun deserialize(decoder: Decoder): ByteVector {
            return ByteVector(decoder.decodeString())
        }
    }
}

@Serializable(with = ByteVector32.Serializer::class)
public class ByteVector32(bytes: ByteArray, offset: Int) : ByteVector(bytes, offset, 32) {
    public constructor(bytes: ByteArray) : this(bytes, 0)
    public constructor(input: String) : this(Hex.decode(input), 0)
    public constructor(input: ByteVector) : this(input.bytes, input.offset)

    override fun update(i: Int, b: Byte): ByteVector32 {
        val newbytes = toByteArray()
        newbytes[i] = b
        return ByteVector32(newbytes)
    }

    override fun reversed(): ByteVector32 = ByteVector32(super.toByteArray().reversedArray())

    public companion object {
        @JvmField
        public val Zeroes: ByteVector32 = ByteVector32("0000000000000000000000000000000000000000000000000000000000000000")

        @JvmField
        public val One: ByteVector32 = ByteVector32("0100000000000000000000000000000000000000000000000000000000000000")

        @JvmStatic
        public fun fromValidHex(input: String): ByteVector32 = ByteVector32(input)
    }

    public object Serializer: KSerializer<ByteVector32> {
        override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("ByteVector32", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: ByteVector32) {
            encoder.encodeString(value.toHex())
        }

        override fun deserialize(decoder: Decoder): ByteVector32 {
            return ByteVector32(decoder.decodeString())
        }
    }
}

@Serializable(with = ByteVector64.Serializer::class)
public class ByteVector64(bytes: ByteArray, offset: Int) : ByteVector(bytes, offset, 64) {
    public constructor(bytes: ByteArray) : this(bytes, 0)
    public constructor(input: String) : this(Hex.decode(input), 0)

    public companion object {
        @JvmField
        public val Zeroes: ByteVector64 = ByteVector64("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

        @JvmStatic
        public fun fromValidHex(input: String): ByteVector64 = ByteVector64(input)
    }

    public object Serializer: KSerializer<ByteVector64> {
        override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("ByteVector64", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: ByteVector64) {
            encoder.encodeString(value.toHex())
        }

        override fun deserialize(decoder: Decoder): ByteVector64 {
            return ByteVector64(decoder.decodeString())
        }
    }
}

public fun ByteArray.byteVector(): ByteVector = ByteVector(this)

public fun ByteArray.byteVector32(): ByteVector32 = ByteVector32(this)

public fun ByteArray.byteVector64(): ByteVector64 = ByteVector64(this)
