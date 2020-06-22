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

import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.Hex
import fr.acinq.bitcoin.fixSize
import kotlinx.cinterop.*
import fr.acinq.bitcoin.io.ByteArrayInput
import platform.posix.size_tVar
import secp256k1.*

public actual object Secp256k1 {
    private const val SIG_FORMAT_UNKNOWN = 0
    private const val SIG_FORMAT_COMPACT = 1
    private const val SIG_FORMAT_DER = 2

    private val ctx: CPointer<secp256k1_context>? by lazy {
        secp256k1_context_create((SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_SIGN or SECP256K1_FLAGS_BIT_CONTEXT_VERIFY).toUInt())
    }

    public actual fun computePublicKey(priv: ByteArray): ByteArray {
        require(ctx != null)
        require(priv.size == 32)
        memScoped {
            val nativePub = nativeHeap.alloc<secp256k1_pubkey>()
            val nativePriv = toNat(priv)
            var result = secp256k1_ec_pubkey_create(ctx, nativePub.ptr, nativePriv)
            require(result == 1)
            return serializePubkey(nativePub)
        }
    }

    public actual fun parsePublicKey(pub: ByteArray): ByteArray {
        require(ctx != null)
        require(pub.size == 33 || pub.size == 65)
        memScoped {
            val nativePub = nativeHeap.alloc<secp256k1_pubkey>()
            var result = secp256k1_ec_pubkey_parse(ctx, nativePub.ptr, toNat(pub), pub.size.toULong())
            require(result == 1)
            val len = cValuesOf(65UL)
            val ser = nativeHeap.allocArray<UByteVar>(65)
            result = secp256k1_ec_pubkey_serialize(ctx, ser, len, nativePub.ptr, SECP256K1_EC_UNCOMPRESSED)
            require(result == 1)
            val output = fromNat(ser, 65)
            return output
        }
    }

    public actual fun ecdh(priv: ByteArray, pub: ByteArray): ByteArray {
        require(ctx != null)
        require(priv.size == 32)
        require(pub.size == 33)
        memScoped {
            val natPriv = toNat(priv)
            val natPubBytes = toNat(pub)
            val natPub = nativeHeap.alloc<secp256k1_pubkey>()
            val natOutput = nativeHeap.allocArray<UByteVar>(32)
            var result = secp256k1_ec_pubkey_parse(ctx, natPub.ptr, natPubBytes, 33UL)
            require(result == 1)
            result = secp256k1_ecdh(ctx, natOutput, natPub.ptr, natPriv, null, null)
            require(result == 1)
            val output = fromNat(natOutput, 32)
            return output
        }
    }

    public actual fun privateKeyAdd(priv1: ByteArray, priv2: ByteArray): ByteArray {
        require(ctx != null)
        require(priv1.size == 32)
        require(priv2.size == 32)
        memScoped {
            val natPriv1 = toNat(priv1)
            val natPriv2 = toNat(priv2)
            var result = secp256k1_ec_privkey_tweak_add(ctx, natPriv1, natPriv2)
            require(result == 1)
            val output = fromNat(natPriv1, 32)
            return output
        }
    }

    public actual fun privateKeyNegate(priv: ByteArray): ByteArray {
        require(ctx != null)
        require(priv.size == 32)
        memScoped {
            val natPriv = toNat(priv)
            var result = secp256k1_ec_privkey_negate(ctx, natPriv)
            require(result == 1)
            val output = fromNat(natPriv, 32)
            return output
        }
    }

    public actual fun privateKeyMul(priv: ByteArray, tweak: ByteArray): ByteArray {
        require(ctx != null)
        require(priv.size == 32)
        require(tweak.size == 32)
        memScoped {
            val natPriv = toNat(priv)
            val natTweak = toNat(tweak)
            var result = secp256k1_ec_privkey_tweak_mul(ctx, natPriv, natTweak)
            require(result == 1)
            val output = fromNat(natPriv, 32)
            return output
        }
    }

    public actual fun publicKeyAdd(pub1: ByteArray, pub2: ByteArray): ByteArray {
        require(ctx != null)
        memScoped {
            val pubkey1 = convertPublicKey(pub1)
            val pubkey2 = convertPublicKey(pub2)
            val combined = nativeHeap.alloc<secp256k1_pubkey>()
            val pubkeys = cValuesOf(pubkey1.ptr, pubkey2.ptr)
            var result = secp256k1_ec_pubkey_combine(ctx, combined.ptr, pubkeys, 2.toULong())
            require(result == 1)
            return serializePubkey(combined)
        }
    }

    public actual fun publicKeyNegate(pub: ByteArray): ByteArray {
        require(ctx != null)
        memScoped {
            val pubkey = convertPublicKey(pub)
            var result = secp256k1_ec_pubkey_negate(ctx, pubkey.ptr)
            require(result == 1)
            return serializePubkey(pubkey)
        }
    }

    public actual fun publicKeyMul(pub: ByteArray, tweak: ByteArray): ByteArray {
        require(ctx != null)
        memScoped {
            val pubkey = convertPublicKey(pub)
            val nativeTweak = toNat(tweak)
            var result = secp256k1_ec_pubkey_tweak_mul(ctx, pubkey.ptr, nativeTweak)
            require(result == 1)
            return serializePubkey(pubkey)
        }
    }

    public actual fun sign(data: ByteArray, priv: ByteArray): ByteArray {
        require(ctx != null)
        require(priv.size == 32)
        require(data.size == 32)
        memScoped {
            val natPriv = toNat(priv)
            val natData = toNat(data)
            val natSig = nativeHeap.alloc<secp256k1_ecdsa_signature>()
            var result = secp256k1_ecdsa_sign(ctx, natSig.ptr, natData, natPriv, null, null);
            require(result == 1)
            val natCompact = nativeHeap.allocArray<UByteVar>(64)
            result = secp256k1_ecdsa_signature_serialize_compact(ctx, natCompact, natSig.ptr)
            require(result == 1)
            val output = fromNat(natCompact, 64)
            return output
        }
    }

    private fun GetSignatureFormat(size: Int): Int {
        return when (size) {
            64 -> SIG_FORMAT_COMPACT
            70, 71, 72, 73 -> SIG_FORMAT_DER
            else -> SIG_FORMAT_UNKNOWN
        }
    }

    public actual fun verify(data: ByteArray, sig: ByteArray, pub: ByteArray): Boolean {
        require(ctx != null)
        require(data.size == 32)
        require(pub.size == 33 || pub.size == 65)
        memScoped {
            val natPub = toNat(pub)
            val pubkey = nativeHeap.alloc<secp256k1_pubkey>()
            var result = secp256k1_ec_pubkey_parse(ctx, pubkey.ptr, natPub, pub.size.toULong())
            require(result == 1)
            val natData = toNat(data)
            val parsedSig = convertSignature(sig)
            result = secp256k1_ecdsa_verify(ctx, parsedSig.ptr, natData, pubkey.ptr)
            return result == 1
        }
    }

    public actual fun compact2der(input: ByteArray): ByteArray {
        require(ctx != null)
        require(input.size == 64)
        memScoped {
            val inputBytes = toNat(input)
            val sig = nativeHeap.alloc<secp256k1_ecdsa_signature>()
            var result = secp256k1_ecdsa_signature_parse_compact(ctx, sig.ptr, inputBytes)
            require(result == 1)
            val len = alloc<size_tVar>()
            len.value = 73UL
            val output = nativeHeap.allocArray<UByteVar>(73)
            result = secp256k1_ecdsa_signature_serialize_der(ctx, output, len.ptr, sig.ptr)
            require(result == 1)
            return fromNat(output, len.value.toInt())
        }
    }

    public actual fun der2compact(input: ByteArray): ByteArray {
        require(ctx != null)
        require(input.size >= 70 && input.size <= 73) { "signature size is not compatible with DER format" }
        memScoped {
            val inputBytes = toNat(input)
            val sig = nativeHeap.alloc<secp256k1_ecdsa_signature>()
            var result = secp256k1_ecdsa_signature_parse_der(ctx, sig.ptr, inputBytes, input.size.toULong())
            assert(result == 1) { "cannot parse DER signature" }
            val output = nativeHeap.allocArray<UByteVar>(64)
            result = secp256k1_ecdsa_signature_serialize_compact(ctx, output, sig.ptr)
            require(result == 1)
            return fromNat(output, 64)
        }
    }

    private fun dropZeroAndFixSize(input: ByteArray, size: Int) = fixSize(input.dropWhile { it == 0.toByte() }.toByteArray(), size)

    public actual fun signatureNormalize(input: ByteArray): Pair<ByteArray, Boolean> {
        require(ctx != null)
        val (r, s) = Crypto.decodeSignatureLax(ByteArrayInput(input))
        val compact = dropZeroAndFixSize(r, 32) + dropZeroAndFixSize(s, 32)
        memScoped {
            val sig = convertSignature(compact)
            val normalized = nativeHeap.alloc<secp256k1_ecdsa_signature>()
            val isHighS = secp256k1_ecdsa_signature_normalize(ctx, normalized.ptr, sig.ptr)
            val output = nativeHeap.allocArray<UByteVar>(64)
            val result = secp256k1_ecdsa_signature_serialize_compact(ctx, output, normalized.ptr)
            require(result == 1) { "cannot serialize signature" }
            return Pair(fromNat(output, 64), isHighS == 1)
        }
    }

    public actual fun recoverPublicKey(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        require(ctx != null)
        memScoped {
            val nativeSig = convertRecoverableSignature(sig, recid)
            val nativeMessage = toNat(message)
            val pubkey = nativeHeap.alloc<secp256k1_pubkey>()
            val result = secp256k1_ecdsa_recover(ctx, pubkey.ptr, nativeSig.ptr, nativeMessage)
            require(result == 1) { "cannot recover pubkey" }
            return serializePubkey(pubkey)
        }
    }

    private fun toNat(input: ByteArray): CArrayPointer<UByteVar> {
        val nat = nativeHeap.allocArray<UByteVar>(input.size)
        for (i in input.indices) nat[i] = input[i].toUByte()
        return nat
    }

    private fun fromNat(input: CArrayPointer<UByteVar>, len: Int): ByteArray {
        val output = ByteArray(len)
        for (i in 0 until len) output[i] = input[i].toByte()
        return output
    }

    private fun convertPublicKey(input: ByteArray): secp256k1_pubkey {
        val pub = nativeHeap.alloc<secp256k1_pubkey>()
        val result = secp256k1_ec_pubkey_parse(ctx, pub.ptr, toNat(input), input.size.toULong())
        require(result == 1) { "cannot parse pubkey" }
        return pub
    }

    private fun convertSignature(input: ByteArray): secp256k1_ecdsa_signature {
        val sigFormat = GetSignatureFormat(input.size)
        val sig = nativeHeap.alloc<secp256k1_ecdsa_signature>()
        val nativeBytes = toNat(input)
        val result = when (sigFormat) {
            SIG_FORMAT_COMPACT -> secp256k1_ecdsa_signature_parse_compact(ctx, sig.ptr, nativeBytes)
            SIG_FORMAT_DER -> secp256k1_ecdsa_signature_parse_der(ctx, sig.ptr, nativeBytes, input.size.toULong())
            else -> 0
        }
        require(result == 1) { "cannot parse signature (size = ${input.size}, format = $sigFormat sig = ${Hex.encode(input)}" }
        return sig
    }

    private fun convertRecoverableSignature(input: ByteArray, recid: Int): secp256k1_ecdsa_recoverable_signature {
        require(input.size == 64)
        val sig = nativeHeap.alloc<secp256k1_ecdsa_recoverable_signature>()
        val result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, sig.ptr, toNat(input), recid)
        require(result == 1) { "cannot parse recoverable signature" }
        return sig
    }

    private fun serializePubkey(input: secp256k1_pubkey): ByteArray {
        val len = cValuesOf(33UL)
        val ser = nativeHeap.allocArray<UByteVar>(33)
        val result = secp256k1_ec_pubkey_serialize(ctx, ser, len, input.ptr, SECP256K1_EC_COMPRESSED)
        require(result == 1) { "cannot serialize pubkey" }
        val output = fromNat(ser, 33)
        return output
    }

}