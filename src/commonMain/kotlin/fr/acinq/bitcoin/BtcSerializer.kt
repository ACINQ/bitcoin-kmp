package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Pack
import kotlinx.io.*
import kotlinx.serialization.InternalSerializationApi
import kotlin.jvm.JvmStatic

@InternalSerializationApi
abstract class BtcSerializer<T> {
    /**
     * write a message to a stream
     *
     * @param message   message
     * @param out output stream
     */
    abstract fun write(message: T, out: OutputStream, protocolVersion: Long)

    fun write(message: T, out: OutputStream): Unit = write(message, out, Protocol.PROTOCOL_VERSION)

    /**
     * write a message to a byte array
     *
     * @param message message
     * @return a serialized message
     */
    fun write(message: T, protocolVersion: Long): ByteArray {
        val out = ByteArrayOutputStream()
        write(message, out, protocolVersion)
        return out.toByteArray()
    }

    open fun write(message: T): ByteArray = write(message, Protocol.PROTOCOL_VERSION)

    /**
     * read a message from a stream
     *
     * @param in input stream
     * @return a deserialized message
     */
    abstract fun read(input: InputStream, protocolVersion: Long): T

    fun read(input: InputStream): T = read(input, Protocol.PROTOCOL_VERSION)

    /**
     * read a message from a byte array
     *
     * @param input serialized message
     * @return a deserialized message
     */
    fun read(input: ByteArray, protocolVersion: Long): T = read(ByteArrayInputStream(input), protocolVersion)

    open fun read(input: ByteArray): T = read(input, Protocol.PROTOCOL_VERSION)

    /**
     * read a message from a hex string
     *
     * @param in message binary data in hex format
     * @return a deserialized message of type T
     */
    fun read(input: String, protocolVersion: Long): T = read(Hex.decode(input), protocolVersion)

    open fun read(input: String): T = read(input, Protocol.PROTOCOL_VERSION)

    open fun validate(message: T) {}

    @ExperimentalStdlibApi
    companion object {
        @JvmStatic
        fun uint8(input: InputStream): Int = input.read()

        @JvmStatic
        fun writeUInt8(input: Int, out: OutputStream): Unit = out.write(input and 0xff)

        @JvmStatic
        fun uint16(input: InputStream): Int {
            val bin = ByteArray(2)
            input.read(bin)
            return Pack.uint16LE(bin, 0)
        }

        @JvmStatic
        fun uint16(input: ByteArray): Int = Pack.uint16LE(input, 0)

        @JvmStatic
        fun uint16BE(input: ByteArray): Int = Pack.uint16BE(input, 0)

        @JvmStatic
        fun writeUInt16(input: Int, out: OutputStream): Unit = out.write(Pack.writeUint16LE(input))

        @JvmStatic
        fun writeUInt16(input: Int): ByteArray = Pack.writeUint16LE(input)

        @JvmStatic
        fun writeUInt16BE(input: Int): ByteArray = Pack.writeUint16BE(input)

        @JvmStatic
        fun uint32(input: InputStream): Long {
            val bin = ByteArray(4)
            input.read(bin)
            return Pack.uint32LE(bin, 0).toLong() and 0xffffffffL
        }

        @JvmStatic
        fun uint32(input: ByteArray): Int {
            return Pack.uint32LE(input, 0)
        }

        @JvmStatic
        fun uint32BE(input: ByteArray): Int {
            return Pack.uint32BE(input, 0)
        }

        @JvmStatic
        fun writeUInt32(input: Long, out: OutputStream): Unit = out.write(Pack.writeUint32LE(input.toInt()))

        @JvmStatic
        fun writeUInt32(input: Long): ByteArray {
            val out = ByteArrayOutputStream()
            writeUInt32(input, out)
            return out.toByteArray()
        }

        @JvmStatic
        fun writeUInt32BE(input: Long, out: OutputStream): Unit = out.write(Pack.writeUint32BE(input.toInt()))

        @JvmStatic
        fun writeUInt32BE(input: Long): ByteArray {
            val out = ByteArrayOutputStream()
            writeUInt32BE(input, out)
            return out.toByteArray()
        }

        @JvmStatic
        fun uint64(input: InputStream): Long {
            val bin = ByteArray(8)
            input.read(bin)
            return Pack.uint64LE(bin, 0)
        }

        @JvmStatic
        fun uint64(input: ByteArray): Long = Pack.uint64LE(input, 0)

        @JvmStatic
        fun uint64BE(input: ByteArray): Long = Pack.uint64BE(input, 0)

        @JvmStatic
        fun writeUInt64(input: Long, out: OutputStream): Unit = out.write(Pack.writeUint64LE(input))

        @JvmStatic
        fun writeUInt64(input: Long): ByteArray = Pack.writeUint64LE(input)

        @JvmStatic
        fun writeUInt64BE(input: Long): ByteArray = Pack.writeUint64BE(input)

        @JvmStatic
        fun varint(blob: ByteArray): Long = varint(ByteArrayInputStream(blob))

        @JvmStatic
        fun varint(input: InputStream): Long {
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
        fun writeVarint(input: Int, out: OutputStream): Unit = writeVarint(input.toLong(), out)

        @JvmStatic
        fun writeVarint(input: Long, out: OutputStream) {
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
        fun bytes(input: InputStream, size: Long): ByteArray = bytes(input, size.toInt())

        @JvmStatic
        fun bytes(input: InputStream, size: Int): ByteArray {
            val blob = ByteArray(size)
            if (size > 0) {
                val count = input.read(blob)
                require(count >= size)
            }
            return blob
        }

        @JvmStatic
        fun writeBytes(input: ByteArray, out: OutputStream): Unit = out.write(input)

        @JvmStatic
        fun writeBytes(input: ByteVector, out: OutputStream): Unit = writeBytes(input.toByteArray(), out)

        @JvmStatic
        fun writeBytes(input: ByteVector32, out: OutputStream): Unit = writeBytes(input.toByteArray(), out)

        @JvmStatic
        fun varstring(input: InputStream): String {
            val length = varint(input)
            val bytes = bytes(input, length)
            val chars = bytes.map { it.toChar() }.toCharArray()
            return String(chars)
        }

        @JvmStatic
        fun writeVarstring(input: String, out: OutputStream): Unit {
            writeVarint(input.length, out)
            writeBytes(input.encodeToByteArray(), out)
        }

        @JvmStatic
        fun hash(input: InputStream): ByteArray = bytes(input, 32) // a hash is always 256 bits

        @JvmStatic
        fun script(input: InputStream): ByteArray {
            val length = varint(input) // read size
            return bytes(input, length) // read bytes
        }

        @JvmStatic
        fun writeScript(input: ByteArray, out: OutputStream) {
            writeVarint(input.size, out)
            writeBytes(input, out)
        }

        @JvmStatic
        fun writeScript(input: ByteVector, out: OutputStream) = writeScript(input.toByteArray(), out)

        fun <T> readCollection(
            input: InputStream,
            reader: BtcSerializer<T>,
            maxElement: Int?,
            protocolVersion: Long
        ): List<T> = readCollection(input, reader::read, maxElement, protocolVersion)

        fun <T> readCollection(
            input: InputStream,
            reader: (InputStream, Long) -> T,
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

        fun <T> readCollection(input: InputStream, reader: BtcSerializer<T>, protocolVersion: Long): List<T> =
            readCollection(input, reader, null, protocolVersion)

        fun <T> writeCollection(
            seq: List<T>,
            output: OutputStream,
            writer: BtcSerializer<T>,
            protocolVersion: Long
        ): Unit = writeCollection(seq, output, writer::write, protocolVersion)

        fun <T> writeCollection(
            seq: List<T>,
            output: OutputStream,
            writer: (T, OutputStream, Long) -> Unit,
            protocolVersion: Long
        ): Unit {
            writeVarint(seq.size, output)
            seq.forEach { writer.invoke(it, output, protocolVersion) }
        }
    }
}

@InternalSerializationApi
interface BtcSerializable<T> {
    fun serializer(): BtcSerializer<T>
}
