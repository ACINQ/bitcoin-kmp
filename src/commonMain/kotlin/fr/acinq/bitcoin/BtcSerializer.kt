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
        public fun uint8(input: Input): Int = input.read()

        @JvmStatic
        public fun writeUInt8(input: Int, out: Output): Unit = out.write(input and 0xff)

        @JvmStatic
        public fun uint16(input: Input): Int {
            val bin = ByteArray(2)
            input.read(bin, 0, 2)
            return Pack.uint16LE(bin, 0)
        }

        @JvmStatic
        public fun uint16(input: ByteArray): Int = Pack.uint16LE(input, 0)

        @JvmStatic
        public fun uint16BE(input: ByteArray): Int = Pack.uint16BE(input, 0)

        @JvmStatic
        public fun writeUInt16(input: Int, out: Output): Unit = out.write(Pack.writeUint16LE(input))

        @JvmStatic
        public fun writeUInt16(input: Int): ByteArray = Pack.writeUint16LE(input)

        @JvmStatic
        public fun writeUInt16BE(input: Int): ByteArray = Pack.writeUint16BE(input)

        @JvmStatic
        public fun uint32(input: Input): Long {
            val bin = ByteArray(4)
            input.read(bin, 0, 4)
            return Pack.uint32LE(bin, 0).toLong() and 0xffffffffL
        }

        @JvmStatic
        public fun uint32(input: ByteArray): Int {
            return Pack.uint32LE(input, 0)
        }

        @JvmStatic
        public fun uint32BE(input: ByteArray): Int {
            return Pack.uint32BE(input, 0)
        }

        @JvmStatic
        public fun writeUInt32(input: Long, out: Output): Unit = out.write(Pack.writeUint32LE(input.toInt()))

        @JvmStatic
        public fun writeUInt32(input: Long): ByteArray {
            val out = ByteArrayOutput()
            writeUInt32(input, out)
            return out.toByteArray()
        }

        @JvmStatic
        public fun writeUInt32BE(input: Long, out: Output): Unit = out.write(Pack.writeUint32BE(input.toInt()))

        @JvmStatic
        public fun writeUInt32BE(input: Long): ByteArray {
            val out = ByteArrayOutput()
            writeUInt32BE(input, out)
            return out.toByteArray()
        }

        @JvmStatic
        public fun uint64(input: Input): Long {
            val bin = ByteArray(8)
            input.read(bin, 0, 8)
            return Pack.uint64LE(bin, 0)
        }

        @JvmStatic
        public fun uint64(input: ByteArray): Long = Pack.uint64LE(input, 0)

        @JvmStatic
        public fun uint64BE(input: ByteArray): Long = Pack.uint64BE(input, 0)

        @JvmStatic
        public fun writeUInt64(input: Long, out: Output): Unit = out.write(Pack.writeUint64LE(input))

        @JvmStatic
        public fun writeUInt64(input: Long): ByteArray = Pack.writeUint64LE(input)

        @JvmStatic
        public fun writeUInt64BE(input: Long): ByteArray = Pack.writeUint64BE(input)

        @JvmStatic
        public fun varint(blob: ByteArray): Long = varint(ByteArrayInput(blob))

        @JvmStatic
        public fun varint(input: Input): Long {
            val first = input.read()
            return when {
                first < 0xfd -> first.toLong()
                first == 0xfd -> uint16(input).toLong()
                first == 0xfe -> uint32(input)
                first == 0xff -> uint64(input)
                else -> {
                    throw IllegalArgumentException("invalid first byte $first for varint type")
                }
            }
        }

        @JvmStatic
        public fun writeVarint(input: Int, out: Output): Unit = writeVarint(input.toLong(), out)

        @JvmStatic
        public fun writeVarint(input: Long, out: Output) {
            when {
                input < 0xfdL -> writeUInt8(input.toInt(), out)
                input < 65535L -> {
                    writeUInt8(0xfd, out)
                    writeUInt16(input.toInt(), out)
                }
                input < 1048576L -> {
                    writeUInt8(0xfe, out)
                    writeUInt32(input, out)
                }
                else -> {
                    writeUInt8(0xff, out)
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
            val bytes = bytes(input, length)
            val chars = bytes.map { it.toChar() }.toCharArray()
            return String(chars)
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
            return bytes(input, length) // read bytes
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
            val count = varint(input)
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
