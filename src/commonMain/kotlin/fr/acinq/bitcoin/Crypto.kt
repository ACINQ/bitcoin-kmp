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
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

public object Crypto {
    @JvmStatic
    public fun sha1(input: ByteVector): ByteArray = Digest.sha1().hash(input.toByteArray())

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
    public fun isPrivKeyValid(key: ByteArray): Boolean = Secp256k1.secKeyVerify(key)

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
     * @return an ECDSA signature in compact format (64 bytes)
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

    /**
     * Specify how private keys are tweaked when creating Schnorr signatures
     */
    public sealed class TaprootTweak {
        /**
         * private key is tweaked with H_TapTweak(public key) (this is used for key path spending when no scripts are present)
         */
        public data object KeyPathTweak : TaprootTweak()

        /**
         * private key is tweaked with H_TapTweak(public key || merkle_root) (this is used for key path spending, with specific Merkle root of the script tree).
         */
        public data class ScriptPathTweak(val merkleRoot: ByteVector32) : TaprootTweak()
    }

    /**
     * @param data data to sign (32 bytes)
     * @param privateKey private key
     * @param taprootTweak optional tweak to apply to the private key.
     * @param auxrand32 optional auxiliary random data
     * @return the Schnorr signature of data with private key (optionally tweaked with the tapscript merkle root)
     */
    @JvmStatic
    public fun signSchnorr(data: ByteVector32, privateKey: PrivateKey, taprootTweak: TaprootTweak?, auxrand32: ByteVector32? = null): ByteVector64 {
        val priv = when (taprootTweak) {
            null -> privateKey
            else -> privateKey.tweak(privateKey.xOnlyPublicKey().tweak(taprootTweak))
        }
        val sig = Secp256k1.signSchnorr(data.toByteArray(), priv.value.toByteArray(), auxrand32?.toByteArray()).byteVector64()
        require(verifySignatureSchnorr(data, sig, priv.xOnlyPublicKey())) { "Cannot create Schnorr signature" }
        return sig
    }

    @JvmStatic
    public fun verifySignatureSchnorr(data: ByteVector32, signature: ByteVector, publicKey: XonlyPublicKey): Boolean {
        return Secp256k1.verifySchnorr(signature.toByteArray(), data.toByteArray(), publicKey.value.toByteArray())
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
        val lenR = sig[3].toInt() and 0xff

        // Make sure the length of the S element is still inside the signature.
        if (5 + lenR >= sig.size) return false

        // Extract the length of the S element.
        val lenS = sig[5 + lenR].toInt() and 0xff

        // Verify that the length of the signature matches the sum of the length
        // of the elements.
        if (lenR + lenS + 7 != sig.size) return false

        // Check whether the R element is an integer.
        if (sig[2] != 0x02.toByte()) return false

        // Zero-length integers are not allowed for R.
        if (lenR == 0) return false

        // Negative numbers are not allowed for R.
        if ((sig[4].toInt() and 0x80) != 0) return false

        // Null bytes at the start of R are not allowed, unless R would
        // otherwise be interpreted as a negative number.
        if (lenR > 1 && (sig[4] == 0x00.toByte()) && (sig[5].toInt() and 0x80) == 0) return false

        // Check whether the S element is an integer.
        if (sig[lenR + 4] != 0x02.toByte()) return false

        // Zero-length integers are not allowed for S.
        if (lenS == 0) return false

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
    public fun isLowDERSignature(sig: ByteArray): Boolean = !Secp256k1.signatureNormalize(Secp256k1.der2compact(sig)).second

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

    /**
     * Decode a DER-encoded signature and return a compact signature. Allows for some violations of DER-encoding rules.
     * This is a "port' of Bitcoin Core's ecdsa_signature_parse_der_lax() method at commit d9c7364ac56781a16c7224b2c7a6db9db97f17d8.
     * It is used to verify ECDSA signatures in the context of bitcoin transaction verification.
     * @param derSignature DER-encoded signature
     * @return a compact 64 bytes signature
     */
    @JvmStatic
    public fun decodeSignatureLax(derSignature: ByteArray): ByteVector64 = try {
        var pos = 0
        val output = ByteArray(64)

        /* Sequence tag byte */
        require(derSignature[pos++] == 0x30.toByte())

        var lenbyte = derSignature[pos++].toInt() and 0xff
        if (lenbyte and 0x80 != 0) {
            lenbyte -= 0x80
            pos += lenbyte
        }

        require(derSignature[pos++] == 0x02.toByte())

        fun readLength(): Int {
            lenbyte = derSignature[pos++].toInt() and 0xff
            var len = 0
            if (lenbyte and 0x80 != 0) {
                lenbyte -= 0x80
                while (lenbyte > 0 && derSignature[pos] == 0.toByte()) {
                    pos++
                    lenbyte--
                }
                require(lenbyte < 4)
                while (lenbyte > 0) {
                    len = (len shl 8) + (derSignature[pos].toInt() and 0xff)
                    pos++
                    lenbyte--
                }
            } else {
                len = lenbyte
            }
            return len
        }

        /* Integer tag byte for R */
        var rlen = readLength()
        require(rlen <= derSignature.size - pos)
        var rpos = pos
        pos += rlen

        /* Integer tag byte for S */
        require(pos < derSignature.size && derSignature[pos++] == 0x02.toByte())

        /* Integer length for S */
        var slen = readLength()
        require(slen <= derSignature.size - pos)
        var spos = pos

        /* Ignore leading zeroes in R */
        while (rlen > 0 && derSignature[rpos] == 0.toByte()) {
            rlen--
            rpos++
        }
        /* Ignore leading zeroes in S */
        while (slen > 0 && derSignature[spos] == 0.toByte()) {
            slen--
            spos++
        }

        // if r or s are too large, we return an invalid signature
        if (rlen > 32 || slen > 32) return ByteVector64.Zeroes

        /* Copy R value */
        derSignature.copyInto(output, 32 - rlen, rpos, rpos + rlen)

        /* Copy S value */
        derSignature.copyInto(output, 64 - slen, spos, spos + slen)

        output.byteVector64()
    } catch (_: IllegalArgumentException) {
        ByteVector64.Zeroes
    } catch (_: IndexOutOfBoundsException) {
        ByteVector64.Zeroes
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

    /**
     * @param input data to be hashed
     * @param tag tag name
     * @return the tagged hash of input as defined in BIP340
     */
    @JvmStatic
    public fun taggedHash(input: ByteArray, tag: String): ByteVector32 {
        val hashedTag = sha256(tag.encodeToByteArray())
        return sha256(hashedTag + hashedTag + input).byteVector32()
    }
}
