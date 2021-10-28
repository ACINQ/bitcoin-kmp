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

import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_DERSIG
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_LOW_S
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_STRICTENC
import fr.acinq.bitcoin.crypto.Digest
import fr.acinq.bitcoin.crypto.hmac
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

public object Crypto {
    public fun sha1(input: ByteVector): ByteArray =
        Digest.sha1().hash(input.toByteArray())

    @JvmStatic
    public fun sha256(input: ByteArray, offset: Int, len: Int): ByteArray =
        Digest.sha256().hash(input, offset, len)

    @JvmStatic
    public fun sha256(input: ByteArray): ByteArray =
        sha256(input, 0, input.size)

    @JvmStatic
    public fun sha256(input: ByteVector): ByteArray =
        sha256(input.toByteArray(), 0, input.size())

    @JvmStatic
    public fun ripemd160(input: ByteArray, offset: Int, len: Int): ByteArray =
        Digest.ripemd160().hash(input, offset, len)

    @JvmStatic
    public fun ripemd160(input: ByteArray): ByteArray =
        ripemd160(input, 0, input.size)

    @JvmStatic
    public fun ripemd160(input: ByteVector): ByteArray =
        ripemd160(input.toByteArray(), 0, input.size())

    @JvmStatic
    public fun hash256(input: ByteArray, offset: Int, len: Int): ByteArray =
        Digest.sha256().let { it.hash(it.hash(input, offset, len)) }

    @JvmStatic
    public fun hash256(input: ByteArray): ByteArray =
        hash256(input, 0, input.size)

    @JvmStatic
    public fun hash256(input: ByteVector): ByteArray =
        hash256(input.toByteArray(), 0, input.size())

    @JvmStatic
    public fun hash160(input: ByteArray, offset: Int, len: Int): ByteArray =
        Digest.ripemd160().hash(Digest.sha256().hash(input, offset, len))

    @JvmStatic
    public fun hash160(input: ByteArray): ByteArray = hash160(input, 0, input.size)

    @JvmStatic
    public fun hash160(input: ByteVector): ByteArray =
        hash160(input.toByteArray(), 0, input.size())

    @JvmStatic
    public fun hmac512(key: ByteArray, data: ByteArray): ByteArray {
        return Digest.sha512().hmac(key, data, 128)
    }

    /**
     * Computes ecdh using secp256k1's variant: sha256(priv * pub serialized in compressed format)
     *
     * @param priv private value
     * @param pub  public value
     * @return ecdh(priv, pub) as computed by libsecp256k1
     */
    @JvmStatic
    public fun ecdh(priv: PrivateKey, pub: PublicKey): ByteArray {
        return Secp256k1.ecdh(priv.value.toByteArray(), pub.value.toByteArray())
    }

    @JvmStatic
    public fun isPubKeyValid(key: ByteArray): Boolean = try {
        Secp256k1.pubkeyParse(key)
        true
    } catch (e: Throwable) {
        false
    }

    @JvmStatic
    public fun isPubKeyCompressedOrUncompressed(key: ByteArray): Boolean {
        return isPubKeyCompressed(key) || isPubKeyUncompressed(key)
    }

    @JvmStatic
    public fun isPubKeyCompressed(key: ByteArray): Boolean = when {
        key.size == 33 && (key[0] == 2.toByte() || key[0] == 3.toByte()) -> true
        else -> false
    }

    @JvmStatic
    public fun isPubKeyUncompressed(key: ByteArray): Boolean = when {
        key.size == 65 && key[0] == 4.toByte() -> true
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
    @JvmStatic
    public fun sign(data: ByteArray, privateKey: PrivateKey): ByteVector64 {
        val bin = Secp256k1.sign(data, privateKey.value.toByteArray())
        return ByteVector64(bin)
    }

    @JvmStatic
    public fun sign(data: ByteVector32, privateKey: PrivateKey): ByteVector64 =
        sign(data.toByteArray(), privateKey)

    /**
     * @param data      data
     * @param signature signature
     * @param publicKey public key
     * @return true is signature is valid for this data with this public key
     */
    @JvmStatic
    public fun verifySignature(data: ByteArray, signature: ByteVector64, publicKey: PublicKey): Boolean {
        return Secp256k1.verify(
            signature.toByteArray(),
            data,
            publicKey.value.toByteArray()
        )
    }

    public fun verifySignature(data: ByteVector32, signature: ByteVector64, publicKey: PublicKey): Boolean =
        verifySignature(data.toByteArray(), signature, publicKey)

    private fun dropZeroAndFixSize(input: ByteArray, size: Int) = fixSize(input.dropWhile { it == 0.toByte() }.toByteArray(), size)

    @JvmStatic
    public fun compact2der(signature: ByteVector64): ByteVector {
        val normalized = Secp256k1.signatureNormalize(signature.toByteArray()).first
        val der = Secp256k1.compact2der(normalized)
        return ByteVector(der)
    }

    @JvmStatic
    public fun der2compact(signature: ByteArray): ByteVector64 {
        val (r, s) = decodeSignatureLax(ByteArrayInput(signature))
        val lax = dropZeroAndFixSize(r, 32) + dropZeroAndFixSize(s, 32)
        return ByteVector64(Secp256k1.signatureNormalize(lax).first)
    }

    @JvmStatic
    public fun normalize(signature: ByteArray): Pair<ByteVector64, Boolean> {
        val (r, s) = decodeSignatureLax(ByteArrayInput(signature))
        val compact = dropZeroAndFixSize(r, 32) + dropZeroAndFixSize(s, 32)
        return Secp256k1.signatureNormalize(compact).let { ByteVector64(it.first) to it.second }
    }

    @JvmStatic
    public fun isDERSignature(sig: ByteArray): Boolean {
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

    /**
     * @param sig signature (DER encoded, without a trailing sighash byte)
     * @return true if the input is a "low S" signature
     */
    @JvmStatic
    public fun isLowDERSignature(sig: ByteArray): Boolean = !Secp256k1.signatureNormalize(sig).second

    /**
     * @param sig signature (DER encoded + a trailing sighash byte)
     * @return true if the trailing sighash byte is valid
     */
    @JvmStatic
    public fun isDefinedHashTypeSignature(sig: ByteArray): Boolean = if (sig.isEmpty()) false else {
        val hashType = (sig.last().toInt() and 0xff) and (SigHash.SIGHASH_ANYONECANPAY.inv())
        !((hashType < SigHash.SIGHASH_ALL || hashType > SigHash.SIGHASH_SINGLE))
    }

    /**
     * @param sig signature in Bitcoin format (DER encoded + 1 trailing sighash byte)
     * @param flags script flags
     * @return true if the signature is properly encoded
     */
    @JvmStatic
    public fun checkSignatureEncoding(sig: ByteArray, flags: Int): Boolean {
        // Empty signature. Not strictly DER encoded, but allowed to provide a
        // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
        return when {
            sig.isEmpty() -> true
            (flags and (SCRIPT_VERIFY_DERSIG or SCRIPT_VERIFY_LOW_S or SCRIPT_VERIFY_STRICTENC)) != 0 && !isDERSignature(sig) -> false
            (flags and SCRIPT_VERIFY_LOW_S) != 0 && !isLowDERSignature(sig.dropLast(1).toByteArray()) -> false // drop the sighash byte
            (flags and SCRIPT_VERIFY_STRICTENC) != 0 && !isDefinedHashTypeSignature(sig) -> false
            else -> true
        }
    }

    /**
     * @param key public key
     * @param flags script flags
     * @param sigVersion signature version (legacy or segwit)
     * @return true if the pubkey is properly encoded
     */
    @JvmStatic
    public fun checkPubKeyEncoding(key: ByteArray, flags: Int, sigVersion: Int): Boolean {
        if ((flags and SCRIPT_VERIFY_STRICTENC) != 0) {
            require(isPubKeyCompressedOrUncompressed(key)) { "invalid public key" }
        }
        // Only compressed keys are accepted in segwit
        if ((flags and ScriptFlags.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && sigVersion == SigVersion.SIGVERSION_WITNESS_V0) {
            require(isPubKeyCompressed(key)) { "public key must be compressed in segwit" }
        }
        return true
    }

    @JvmStatic
    public fun decodeSignatureLax(input: ByteArrayInput): Pair<ByteArray, ByteArray> {
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
        input.read(r, 0, lenR)
        require(input.read() == 0x02)
        val lenS = readLength()
        val s = ByteArray(lenS)
        input.read(s, 0, lenS)
        return Pair(r, s)
    }

    /**
     * Recover public keys from a signature and the message that was signed. This method will return 2 public keys, and the signature
     * can be verified with both, but only one of them matches that private key that was used to generate the signature.
     * @param sig signature
     * @param message message that was signed
     * @return a (pub1, pub2) tuple where pub1 and pub2 are candidates public keys. If you have the recovery id  then use
     *         pub1 if the recovery id is even and pub2 if it is odd
     */
    @JvmStatic
    public fun recoverPublicKey(sig: ByteVector64, message: ByteArray): Pair<PublicKey, PublicKey> {
        val p0 = recoverPublicKey(sig, message, 0)
        val p1 = recoverPublicKey(sig, message, 1)
        return Pair(p0, p1)
    }

    /**
     * Recover public keys from a signature, the message that was signed, and the recovery id (i.e. the sign of
     * the recovered public key)
     * @param sig signature
     * @param message that was signed
     * @recid recovery id
     * @return the recovered public key
     */
    @JvmStatic
    public fun recoverPublicKey(sig: ByteVector64, message: ByteArray, recid: Int): PublicKey {
        return PublicKey(PublicKey.compress(Secp256k1.ecdsaRecover(sig.toByteArray(), message, recid)))
    }
}