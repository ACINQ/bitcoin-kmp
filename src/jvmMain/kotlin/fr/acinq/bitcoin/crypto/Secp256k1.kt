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
import fr.acinq.bitcoin.fixSize
import fr.acinq.bitcoin.io.ByteArrayInput
import org.bitcoin.NativeSecp256k1
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequenceGenerator
import java.io.ByteArrayOutputStream
import java.math.BigInteger

public actual object Secp256k1 {

    private val N2 = BigInteger("57896044618658097711785492504343953926418782139537452191302581570759080747168")
    private val N = BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337")

    public actual fun computePublicKey(priv: ByteArray): ByteArray {
        val pub = NativeSecp256k1.computePubkey(priv)
        // secp256k1 returns pubkeys in uncompressed format, we need to compress them
        pub[0] = if (pub[64].rem(2) == 0) 0x02.toByte() else 0x03.toByte()
        return pub.copyOfRange(0, 33)
    }

    public actual fun parsePublicKey(pub: ByteArray): ByteArray {
        return NativeSecp256k1.parsePubkey(pub)
    }

    public actual fun ecdh(priv: ByteArray, pub: ByteArray): ByteArray {
        // pub is compressed, we need to uncompress it first
        val pub1 = NativeSecp256k1.parsePubkey(pub)
        return NativeSecp256k1.createECDHSecret(priv, pub1)
    }

    public actual fun privateKeyAdd(priv1: ByteArray, priv2: ByteArray): ByteArray {
        return NativeSecp256k1.privKeyTweakAdd(priv1, priv2)
    }

    public actual fun privateKeyNegate(priv: ByteArray): ByteArray {
        return NativeSecp256k1.privKeyNegate(priv)
    }

    public actual fun privateKeyMul(priv: ByteArray, tweak: ByteArray): ByteArray {
        return NativeSecp256k1.privKeyTweakMul(priv, tweak)
    }

    public actual fun publicKeyAdd(pub1: ByteArray, pub2: ByteArray): ByteArray {
        return NativeSecp256k1.pubKeyAdd(pub1, pub2)
    }

    public actual fun publicKeyNegate(pub: ByteArray): ByteArray {
        return NativeSecp256k1.pubKeyNegate(pub)
    }

    public actual fun publicKeyMul(pub: ByteArray, tweak: ByteArray): ByteArray {
        return NativeSecp256k1.pubKeyTweakMul(pub, tweak)
    }

    public actual fun sign(data: ByteArray, priv: ByteArray): ByteArray {
        return NativeSecp256k1.signCompact(data, priv)
    }

    public actual fun verify(data: ByteArray, sig: ByteArray, pub: ByteArray): Boolean {
        return NativeSecp256k1.verify(data, sig, pub)
    }

    public actual fun compact2der(input: ByteArray): ByteArray {
        val r = BigInteger(1, input.take(32).toByteArray())
        val s = BigInteger(1, input.takeLast(32).toByteArray())
        val s1 = if (s >= N2) N.minus(s) else s
        val bos = ByteArrayOutputStream(73)
        val seq = DERSequenceGenerator(bos)
        seq.addObject(ASN1Integer(r))
        seq.addObject(ASN1Integer(s1))
        seq.close()
        return bos.toByteArray()
    }

    private fun dropZeroAndFixSize(input: ByteArray, size: Int) = fixSize(input.dropWhile { it == 0.toByte() }.toByteArray(), size)

    public actual fun der2compact(input: ByteArray): ByteArray = signatureNormalize(input).first

    public actual fun signatureNormalize(input: ByteArray): Pair<ByteArray, Boolean> {
        val (r, s) = Crypto.decodeSignatureLax(ByteArrayInput(input))
        return if (BigInteger(1, s).compareTo(N2) >= 0) {
            Pair(dropZeroAndFixSize(r, 32) + dropZeroAndFixSize(N.minus(BigInteger(1, s)).toByteArray(), 32), true)
        } else Pair(dropZeroAndFixSize(r, 32) + dropZeroAndFixSize(s, 32), false)
    }

    public actual fun recoverPublicKey(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        return NativeSecp256k1.ecdsaRecover(sig, message, recid)
    }
}