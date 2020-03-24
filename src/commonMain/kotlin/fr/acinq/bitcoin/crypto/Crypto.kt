package fr.acinq.bitcoin.crypto

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_DERSIG
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_LOW_S
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_STRICTENC
import kotlinx.io.ByteArrayInputStream
import kotlinx.serialization.InternalSerializationApi

object Crypto {
    fun sha1(input: ByteVector): ByteArray = Sha1.hash(input.toByteArray())

    fun sha256(input: ByteArray, offset: Int, len: Int) = Sha256.hash(input, offset, len)

    fun sha256(input: ByteArray) = sha256(input, 0, input.size)

    fun sha256(input: ByteVector) = sha256(input.toByteArray(), 0, input.size())

    fun ripemd160(input: ByteArray, offset: Int, len: Int) = Ripemd160.hash(input, offset, len)

    fun ripemd160(input: ByteArray) = ripemd160(input, 0, input.size)

    fun ripemd160(input: ByteVector) = ripemd160(input.toByteArray(), 0, input.size())

    fun hash256(input: ByteArray, offset: Int, len: Int) = Sha256.hash(Sha256.hash(input, offset, len))

    fun hash256(input: ByteArray) = hash256(input, 0, input.size)

    fun hash256(input: ByteVector) = hash256(input.toByteArray(), 0, input.size())

    fun hash160(input: ByteArray, offset: Int, len: Int) = Ripemd160.hash(Sha256.hash(input, offset, len))

    fun hash160(input: ByteArray) = hash160(input, 0, input.size)

    fun hash160(input: ByteVector) = hash160(input.toByteArray(), 0, input.size())

    fun isPubKeyValid(key: ByteArray): Boolean = when {
        key.size == 65 && (key[0] == 4.toByte() || key[0] == 6.toByte() || key[0] == 7.toByte()) -> true
        key.size == 33 && (key[0] == 2.toByte() || key[0] == 3.toByte()) -> true
        else -> false
    }

    fun isPubKeyCompressedOrUncompressed(key: ByteArray): Boolean = when {
        key.size == 65 && key[0] == 4.toByte() -> true
        key.size == 33 && (key[0] == 2.toByte() || key[0] == 3.toByte()) -> true
        else -> false
    }

    fun isPubKeyCompressed(key: ByteArray): Boolean = when {
        key.size == 33 && (key[0] == 2.toByte() || key[0] == 3.toByte()) -> true
        else -> false
    }

    /**
     * Sign data with a private key, using RCF6979 deterministic signatures
     *
     * @param data       data to sign
     * @param privateKey private key. If you are using bitcoin "compressed" private keys make sure to only use the first 32 bytes of
     *                   the key (there is an extra "1" appended to the key)
     * @return a (r, s) ECDSA signature pair
     */
    fun sign(data: ByteArray, privateKey: PrivateKey): ByteVector64 {
         val bin = Secp256k1.sign(data, privateKey.value.toByteArray())
         return ByteVector64(bin)
    }

    fun sign(data: ByteVector32, privateKey: PrivateKey): ByteVector64 = sign(data.toByteArray(), privateKey)

    /**
     * @param data      data
     * @param signature signature
     * @param publicKey public key
     * @return true is signature is valid for this data with this public key
     */
    fun verifySignature(data: ByteArray, signature: ByteVector64, publicKey: PublicKey): Boolean {
        return Secp256k1.verify(data, signature.toByteArray(), publicKey.value.toByteArray())
    }

    fun verifySignature(data: ByteVector32, signature: ByteVector64, publicKey: PublicKey): Boolean = verifySignature(data.toByteArray(), signature, publicKey)

    fun compact2der(signature: ByteVector64) : ByteVector = ByteVector(Secp256k1.compact2der(signature.toByteArray()))

    @InternalSerializationApi
    fun der2compact(signature: ByteArray) : ByteVector64 = ByteVector64(Secp256k1.der2compact(signature))

    fun isDERSignature(sig: ByteArray): Boolean {
        // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
        // * total-length: 1-byte length descriptor of everything that follows,
        //   excluding the sighash byte.
        // * R-length: 1-byte length descriptor of the R value that follows.
        // * R: arbitrary-length big-endian encoded R value. It must use the shortest
        //   possible encoding for a positive integers (which means no null bytes at
        //   the start, except a single one when the next byte has its highest bit set).
        // * S-length: 1-byte length descriptor of the S value that follows.
        // * S: arbitrary-length big-endian encoded S value. The same rules apply.
        // * sighash: 1-byte value indicating what data is hashed (not part of the DER
        //   signature)

        // Minimum and maximum size constraints.
        if (sig.size < 9) return false
        if (sig.size > 73) return false

        // A signature is of type 0x30 (compound).
        if (sig[0] != 0x30.toByte()) return false

        // Make sure the length covers the entire signature.
        if (sig[1] != (sig.size - 3).toByte()) return false

        // Extract the length of the R element.
        val lenR = sig[3]

        // Make sure the length of the S element is still inside the signature.
        if (5 + lenR >= sig.size) return false

        // Extract the length of the S element.
        val lenS = sig[5 + lenR]

        // Verify that the length of the signature matches the sum of the length
        // of the elements.
        if (lenR + lenS + 7 != sig.size) return false

        // Check whether the R element is an integer.
        if (sig[2] != 0x02.toByte()) return false

        // Zero-length integers are not allowed for R.
        if (lenR == 0.toByte()) return false

        // Negative numbers are not allowed for R.
        if ((sig[4].toInt() and 0x80) != 0) return false

        // Null bytes at the start of R are not allowed, unless R would
        // otherwise be interpreted as a negative number.
        if (lenR > 1 && (sig[4] == 0x00.toByte()) && (sig[5].toInt() and 0x80) == 0) return false

        // Check whether the S element is an integer.
        if (sig[lenR + 4] != 0x02.toByte()) return false

        // Zero-length integers are not allowed for S.
        if (lenS == 0.toByte()) return false

        // Negative numbers are not allowed for S.
        if ((sig[lenR + 6].toInt() and 0x80) != 0) return false

        // Null bytes at the start of S are not allowed, unless S would otherwise be
        // interpreted as a negative number.
        if (lenS > 1 && (sig[lenR + 6] == 0x00.toByte()) && (sig[lenR + 7].toInt() and 0x80) == 0) return false

        return true
    }

    @InternalSerializationApi
    fun isLowDERSignature(sig: ByteArray): Boolean  = !Secp256k1.signatureNormalize(sig).second

    fun isDefinedHashtypeSignature(sig: ByteArray): Boolean = if (sig.isEmpty()) false else {
        val hashType = (sig.last().toInt() and 0xff) and (SigHash.SIGHASH_ANYONECANPAY.inv())
        !((hashType < SigHash.SIGHASH_ALL || hashType > SigHash.SIGHASH_SINGLE))
    }

    @InternalSerializationApi
    fun checkSignatureEncoding(sig: ByteArray, flags: Int): Boolean {
        // Empty signature. Not strictly DER encoded, but allowed to provide a
        // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
        return if (sig.isEmpty()) true
        else if ((flags and (SCRIPT_VERIFY_DERSIG or SCRIPT_VERIFY_LOW_S or SCRIPT_VERIFY_STRICTENC)) != 0 && !isDERSignature(sig)) false
        else if ((flags and SCRIPT_VERIFY_LOW_S) != 0 && !isLowDERSignature(sig)) false
        else if ((flags and SCRIPT_VERIFY_STRICTENC) != 0 && !isDefinedHashtypeSignature(sig)) false
        else true
    }

    fun checkPubKeyEncoding(key: ByteArray, flags: Int, sigVersion: Int): Boolean {
        if ((flags and SCRIPT_VERIFY_STRICTENC) != 0) {
            require(isPubKeyCompressedOrUncompressed(key)) { "invalid public key" }
        }
        // Only compressed keys are accepted in segwit
        if ((flags and ScriptFlags.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && sigVersion == SigVersion.SIGVERSION_WITNESS_V0) {
            require(isPubKeyCompressed(key)) { "public key must be compressed in segwit" }
        }
        return true
    }

    @InternalSerializationApi
    fun decodeSignatureLax(input: ByteArrayInputStream): Pair<ByteArray, ByteArray> {
        require(input.read() == 0x30)

        fun readLength(): Int {
            val len = input.read()
            return if ((len and 0x80) == 0) {
                len
            } else {
                var n = len - 0x80
                var len1 = 0
                while (n > 0) {
                    len1 = (len1 shl 8) + input.read()
                    n -= 1
                }
                len1
            }
        }

        readLength()
        require(input.read() == 0x02)
        val lenR = readLength()
        val r = ByteArray(lenR)
        input.read(r)
        require(input.read() == 0x02)
        val lenS = readLength()
        val s = ByteArray(lenS)
        input.read(s)
        return Pair(r, s)
    }
}