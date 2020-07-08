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
import fr.acinq.bitcoin.io.*
import kotlin.jvm.JvmStatic

@OptIn(ExperimentalUnsignedTypes::class)
public abstract class BtcSerializer<T> {
    /**
     * write a message to a stream
     *
     * @param message   message
     * @param out output stream
     */
    public abstract fun write(message: T, out: Output, protocolVersion: Long)

    public fun write(message: T, out: Output): Unit = write(message, out, Protocol.PROTOCOL_VERSION)

    /**
     * write a message to a byte array
     *
     * @param message message
     * @return a serialized message
     */
    public fun write(message: T, protocolVersion: Long): ByteArray {
        val out = ByteArrayOutput()
        write(message, out, protocolVersion)
        return out.toByteArray()
    }

    public open fun write(message: T): ByteArray = write(message, Protocol.PROTOCOL_VERSION)

    /**
     * read a message from a stream
     *
     * @param input input stream
     * @return a deserialized message
     */
    public abstract fun read(input: Input, protocolVersion: Long): T

    public fun read(input: Input): T = read(input, Protocol.PROTOCOL_VERSION)

    /**
     * read a message from a byte array
     *
     * @param input serialized message
     * @return a deserialized message
     */
    public fun read(input: ByteArray, protocolVersion: Long): T = read(ByteArrayInput(input), protocolVersion)

    public open fun read(input: ByteArray): T = read(input, Protocol.PROTOCOL_VERSION)

    /**
     * read a message from a hex string
     *
     * @param input message binary data in hex format
     * @return a deserialized message of type T
     */
    public fun read(input: String, protocolVersion: Long): T = read(Hex.decode(input), protocolVersion)

    public open fun read(input: String): T = read(input, Protocol.PROTOCOL_VERSION)

    public open fun validate(message: T) {}

    public companion object {
        @JvmStatic
        public fun uint8(input: Input): UByte = input.read().toUByte()

        @JvmStatic
        public fun writeUInt8(input: UByte, out: Output): Unit = out.write(input.toInt() and 0xff)

        @JvmStatic
        public fun uint16(input: Input): UShort = Pack.int16LE(input).toUShort()

        @JvmStatic
        public fun uint16(input: ByteArray): UShort = Pack.int16LE(input).toUShort()

        @JvmStatic
        public fun writeUInt16(input: UShort, out: Output): Unit = Pack.writeInt16LE(input.toShort(), out)

        @JvmStatic
        public fun writeUInt16(input: UShort): ByteArray = Pack.writeInt16LE(input.toShort())

        @JvmStatic
        public fun uint32(input: Input): UInt = Pack.int32LE(input).toUInt()

        @JvmStatic
        public fun uint32(input: ByteArray): UInt = Pack.int32LE(input).toUInt()

        @JvmStatic
        public fun writeUInt32(input: UInt, out: Output): Unit = Pack.writeInt32LE(input.toInt(), out)

        @JvmStatic
        public fun writeUInt32(input: UInt): ByteArray = Pack.writeInt32LE(input.toInt())

        @JvmStatic
        public fun uint64(input: Input): ULong = Pack.int64LE(input).toULong()

        @JvmStatic
        public fun uint64(input: ByteArray): ULong = Pack.int64LE(input).toULong()

        @JvmStatic
        public fun writeUInt64(input: ULong, out: Output): Unit = Pack.writeInt64LE(input.toLong(), out)

        @JvmStatic
        public fun writeUInt64(input: ULong): ByteArray = Pack.writeInt64LE(input.toLong())

        @JvmStatic
        public fun varint(blob: ByteArray): ULong = varint(ByteArrayInput(blob))

        @JvmStatic
        public fun varint(input: Input): ULong {
            val first = input.read()
            return when {
                first < 0xFD -> first.toULong()
                first == 0xFD -> uint16(input).toULong()
                first == 0xFE -> uint32(input).toULong()
                first == 0xFF -> uint64(input)
                else -> {
                    throw IllegalArgumentException("invalid first byte $first for varint type")
                }
            }
        }

        @JvmStatic
        public fun writeVarint(input: Int, out: Output): Unit = writeVarint(input.toULong(), out)

        @JvmStatic
        public fun writeVarint(input: ULong, out: Output) {
            when {
                input < 0xFDuL -> writeUInt8(input.toUByte(), out)
                input < 65535uL -> {
                    writeUInt8(0xFDu, out)
                    writeUInt16(input.toUShort(), out)
                }
                input < 1048576uL -> {
                    writeUInt8(0xFEu, out)
                    writeUInt32(input.toUInt(), out)
                }
                else -> {
                    writeUInt8(0xFFu, out)
                    writeUInt64(input, out)
                }
            }
        }

        @JvmStatic
        public fun bytes(input: Input, size: Long): ByteArray = bytes(input, size.toInt())

        @JvmStatic
        public fun bytes(input: Input, size: Int): ByteArray {
            val blob = ByteArray(size)
            if (size > 0) {
                val count = input.read(blob, 0, size)
                require(count >= size)
            }
            return blob
        }

        @JvmStatic
        public fun writeBytes(input: ByteArray, out: Output): Unit = out.write(input)

        @JvmStatic
        public fun writeBytes(input: ByteVector, out: Output): Unit = writeBytes(input.toByteArray(), out)

        @JvmStatic
        public fun writeBytes(input: ByteVector32, out: Output): Unit = writeBytes(input.toByteArray(), out)

        @JvmStatic
        public fun varstring(input: Input): String {
            val length = varint(input)
            val bytes = bytes(input, length.toInt())
            val chars = bytes.map { it.toChar() }.toCharArray()
            return chars.concatToString()
        }

        @JvmStatic
        @OptIn(ExperimentalStdlibApi::class)
        public fun writeVarstring(input: String, out: Output) {
            writeVarint(input.length, out)
            writeBytes(input.encodeToByteArray(), out)
        }

        @JvmStatic
        public fun hash(input: Input): ByteArray = bytes(input, 32) // a hash is always 256 bits

        @JvmStatic
        public fun script(input: Input): ByteArray {
            val length = varint(input) // read size
            return bytes(input, length.toInt()) // read bytes
        }

        @JvmStatic
        public fun writeScript(input: ByteArray, out: Output) {
            writeVarint(input.size, out)
            writeBytes(input, out)
        }

        @JvmStatic
        public fun writeScript(input: ByteVector, out: Output) { writeScript(input.toByteArray(), out) }

        public fun <T> readCollection(
            input: Input,
            reader: BtcSerializer<T>,
            maxElement: Int?,
            protocolVersion: Long
        ): List<T> = readCollection(input, reader::read, maxElement, protocolVersion)

        public fun <T> readCollection(
            input: Input,
            reader: (Input, Long) -> T,
            maxElement: Int?,
            protocolVersion: Long
        ): List<T> {
            val count = varint(input).toInt()
            if (maxElement != null) require(count <= maxElement) { "invalid length" }
            val items = mutableListOf<T>()
            for (i in 1..count) {
                items += reader(input, protocolVersion)
            }
            return items.toList()
        }

        public fun <T> readCollection(input: Input, reader: BtcSerializer<T>, protocolVersion: Long): List<T> =
            readCollection(input, reader, null, protocolVersion)

        public fun <T> writeCollection(
            seq: List<T>,
            output: Output,
            writer: BtcSerializer<T>,
            protocolVersion: Long
        ): Unit = writeCollection(seq, output, writer::write, protocolVersion)

        public fun <T> writeCollection(
            seq: List<T>,
            output: Output,
            writer: (T, Output, Long) -> Unit,
            protocolVersion: Long
        ) {
            writeVarint(seq.size, output)
            seq.forEach { writer.invoke(it, output, protocolVersion) }
        }
    }
}

public interface BtcSerializable<T> {
    public fun serializer(): BtcSerializer<T>
}
