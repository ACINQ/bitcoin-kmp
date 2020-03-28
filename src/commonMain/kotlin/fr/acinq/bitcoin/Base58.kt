package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Crypto
import fr.acinq.bitcoin.crypto.Pack
import kotlin.jvm.JvmStatic

object Base58 {
    object Prefix {
        const val PubkeyAddress = 0.toByte()
        const val ScriptAddress = 5.toByte()
        const val SecretKey = 128.toByte()
        const val PubkeyAddressTestnet = 111.toByte()
        const val ScriptAddressTestnet = 196.toByte()
        const val SecretKeyTestnet = 239.toByte()
        const val PubkeyAddressSegnet = 30.toByte()
        const val ScriptAddressSegnet = 50.toByte()
        const val SecretKeySegnet = 158.toByte()
    }

    private const val pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    //@formatter:off
    private val mapBase58 = intArrayOf(
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1,
        -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
        -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    )
    //@formatter:on

    @JvmStatic
    fun encode(input: ByteArray): String {
        // Skip & count leading zeroes.
        var zeroes = 0
        var length = 0
        var begin = 0
        var end = input.size
        while (begin != end && input[begin] == 0.toByte()) {
            begin++
            zeroes++
        }
        // Allocate enough space in big-endian base58 representation.
        val size = (end - begin) * 138 / 100 + 1 // log(256) / log(58), rounded up.
        val b58 = ByteArray(size)
        // Process the bytes.
        while (begin != end) {
            var carry = input[begin].toInt() and 0xff
            // Apply "b58 = b58 * 256 + ch".
            var it = b58.size - 1
            var i = 0
            while ((carry != 0 || i < length) && (it >= 0)) {
                carry += 256 * b58[it]
                b58[it] = (carry % 58).toByte()
                carry /= 58
                i++
                it--
            }
            //assert(carry == 0);
            length = i
            begin++
        }
        // Skip leading zeroes in base58 result.
        var it = size - length
        while (it != b58.size && b58[it] == 0.toByte()) {
            it++
        }
        // Translate the result into a string.
        val str = StringBuilder()
        repeat(zeroes) { str.append('1') }
        while (it < b58.size) {
            str.append(pszBase58[b58[it].toInt()])
            it++
        }
        return str.toString()
    }

    @JvmStatic
    fun decode(input: String): ByteArray {
        // Skip leading spaces.
        var psz = 0
        while (psz < input.length && input[psz].isWhitespace()) {
            psz++
        }
        // Skip and count leading '1's.
        var zeroes = 0
        var length = 0
        while (psz < input.length && input[psz] == '1') {
            zeroes++
            psz++
        }
        // Allocate enough space in big-endian base256 representation.
        val size = (input.length - psz) * 733 / 1000 + 1 // log(58) / log(256), rounded up.
        val b256 = ByteArray(size);
        // Process the characters.
        while (psz < input.length && !input[psz].isWhitespace()) {
            // Decode base58 character
            var carry = mapBase58[input[psz].toInt()]
            require(carry != -1)
            var i = 0
            var it = b256.size - 1
            while ((carry != 0 || i < length) && (it >= 0)) {
                carry += 58 * (b256[it].toInt() and 0xff)
                b256[it] = (carry % 256).toByte()
                carry /= 256
                it--
                i++
            }
            //assert(carry == 0);
            length = i
            psz++
        }
        // Skip trailing spaces.
        while (psz < input.length && input[psz].isWhitespace()) psz++
        require(psz == input.length)
        // Skip leading zeroes in b256.
        var it = size - length
        val output = ByteArray(zeroes + b256.size - it)
        while (it < b256.size) {
            output[zeroes] = b256[it]
            zeroes++
            it++
        }
        return output
    }
}

/**
 * https://en.bitcoin.it/wiki/Base58Check_encoding
 * Base58Check is a format based on Base58 and used a lot in bitcoin, for encoding addresses and private keys for
 * example. It includes a prefix (usually a single byte) and a checksum so you know what has been encoded, and that it has
 * been transmitted correctly.
 * For example, to create an address for a public key you could write:
 * {{{
 *   val pub: BinaryData = "0202a406624211f2abbdc68da3df929f938c3399dd79fac1b51b0e4ad1d26a47aa"
 *   val address = Base58Check.encode(Base58.Prefix.PubkeyAddress, Crypto.hash160(pub))
 * }}}
 * And to decode a private key you could write:
 * {{{
 *   // check that is it a mainnet private key
 *   val (Base58.Prefix.SecretKey, priv) = Base58Check.decode("5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn")
 * }}}
 *
 */
object Base58Check {
    fun checksum(data: ByteArray): ByteArray = Crypto.hash256(data).copyOf(4)

    @JvmStatic
    fun encode(prefix: Int, data: ByteArray): String = encode(Pack.writeUint32BE(prefix), data)

    /**
     * Encode data in Base58Check format.
     * For example, to create an address from a public key you could use:
     *
     * @param prefix version prefix (one byte)
     * @param data   date to be encoded
     * @return a Base58 string
     */
    @JvmStatic
    fun encode(prefix: Byte, data: ByteArray): String = encode(arrayOf(prefix).toByteArray(), data)

    @JvmStatic
    fun encode(prefix: Byte, data: ByteVector): String = encode(arrayOf(prefix).toByteArray(), data.toByteArray())

    /**
     *
     * @param prefix version prefix (several bytes, as used with BIP32 ExtendedKeys for example)
     * @param data   data to be encoded
     * @return a Base58 String
     */
    @JvmStatic
    fun encode(prefix: ByteArray, data: ByteArray): String {
        val prefixAndData = prefix + data
        return Base58.encode(prefixAndData + checksum(prefixAndData))
    }

    /**
     * Decodes Base58 data that has been encoded with a single byte prefix
     *
     * @param encoded encoded data
     * @return a (prefix, data) tuple
     * @throws RuntimeException if the checksum that is part of the encoded data cannot be verified
     */
    @JvmStatic
    fun decode(encoded: String): Pair<Byte, ByteArray> {
        val raw = Base58.decode(encoded)
        val versionAndHash = raw.dropLast(4).toByteArray()
        val checksum = raw.takeLast(4).toByteArray()
        require(checksum.contentEquals(Base58Check.checksum(versionAndHash))) { "invalid Base58Check data $encoded" }
        return Pair(versionAndHash[0], versionAndHash.drop(1).toByteArray())
    }

    /**
     * Decodes Base58 data that has been encoded with an integer prefix
     *
     * NB: requirement check will throw an IllegalArgumentException if the checksum that is part of the encoded data cannot be verified
     *
     * @param encoded encoded data
     * @return a (prefix, data) tuple
     */
    @JvmStatic
    fun decodeWithIntPrefix(encoded: String): Pair<Int, ByteArray> {
        val (prefix, data) = decodeWithPrefixLen(encoded, 4)
        return Pair(Pack.uint32BE(prefix), data)
    }

    /**
     * Decodes Base58 data that has been encoded with several bytes prefix
     *
     * NB: requirement check will throw an IllegalArgumentException if the checksum that is part of the encoded data cannot be verified
     *
     * @param encoded encoded data
     * @return a (prefix, data) tuple
     */
    @JvmStatic
    fun decodeWithPrefixLen(encoded: String, prefixLen: Int): Pair<ByteArray, ByteArray> {
        val raw = Base58.decode(encoded)
        val versionAndHash = raw.dropLast(4).toByteArray()
        val checksum = raw.takeLast(4).toByteArray()
        require(checksum.contentEquals(Base58Check.checksum(versionAndHash))) { "invalid Base58Check data $encoded" }
        return Pair(versionAndHash.take(prefixLen).toByteArray(), versionAndHash.drop(prefixLen).toByteArray())
    }
}