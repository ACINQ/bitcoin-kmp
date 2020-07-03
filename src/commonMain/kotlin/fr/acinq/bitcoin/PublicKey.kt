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

import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

public data class PublicKey(@JvmField val value: ByteVector) {
    public constructor(data: ByteArray) : this(ByteVector(data))

    public operator fun plus(that: PublicKey): PublicKey {
        val pub = Secp256k1.pubKeyAdd(
            value.toByteArray(),
            that.value.toByteArray()
        )
        return PublicKey(compress(pub))
    }

    public operator fun times(that: PrivateKey): PublicKey {
        val pub = Secp256k1.pubKeyTweakMul(
            value.toByteArray(),
            that.value.toByteArray()
        )
        return PublicKey(compress(pub))
    }

    /**
     *
     * @return the hash160 of the binary representation of this point. This can be used to generated addresses (the address
     *         of a public key is he base58 encoding of its hash)
     */
    public fun hash160(): ByteArray = Crypto.hash160(value.toByteArray())

    override fun toString(): String = value.toString()

    public fun toUncompressedBin(): ByteArray {
        return Secp256k1.pubkeyParse(value.toByteArray())
    }

    init {
        require(Crypto.isPubKeyValid(value.toByteArray()))
    }

    public companion object {
        @JvmField
        public val Generator: PublicKey = PublicKey(Hex.decode("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))

        @JvmStatic
        public fun compress(pub: ByteArray): ByteArray {
            return if (Crypto.isPubKeyCompressed(pub)) pub else {
                val pub1 = pub.copyOf(33)
                pub1[0] = if (pub.last() % 2 == 0) 2.toByte() else 3.toByte()
                pub1
            }
        }

        @JvmStatic
        public fun fromHex(hex: String): PublicKey = PublicKey(Hex.decode(hex))
    }
}