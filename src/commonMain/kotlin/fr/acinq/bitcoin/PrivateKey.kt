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

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

@Serializable
public data class PrivateKey(@JvmField val value: ByteVector32) {
    public constructor(data: ByteArray) : this(
        when {
            data.size == 32 -> ByteVector32(data.copyOf())
            data.size == 33 && data.last() == 1.toByte() -> ByteVector32(data.copyOf(32))
            else -> throw RuntimeException("invalid private key")
        }
    )

    public constructor(data: ByteVector) : this(data.toByteArray())

    public operator fun plus(that: PrivateKey): PrivateKey =
        PrivateKey(
            Secp256k1.privKeyTweakAdd(
                value.toByteArray(),
                that.value.toByteArray()
            )
        )

    public operator fun minus(that: PrivateKey): PrivateKey =
        plus(
            PrivateKey(
                Secp256k1.privKeyNegate(
                    that.value.toByteArray()
                )
            )
        )

    public operator fun times(that: PrivateKey): PrivateKey =
        PrivateKey(
            Secp256k1.privKeyTweakMul(
                value.toByteArray(),
                that.value.toByteArray()
            )
        )

    public fun publicKey(): PublicKey {
        val pub = Secp256k1.pubkeyCreate(value.toByteArray())
        return PublicKey(PublicKey.compress(pub))
    }

    public fun toBase58(prefix: Byte): String = Base58Check.encode(prefix, value.toByteArray() + 1.toByte())

    public companion object {
        @JvmStatic
        public fun isCompressed(data: ByteArray): Boolean {
            return when {
                data.size == 32 -> false
                data.size == 33 && data.last() == 1.toByte() -> true
                else -> throw IllegalArgumentException("invalid private key ${Hex.encode(data)}")
            }
        }

        @JvmStatic
        public fun fromBase58(value: String, prefix: Byte): Pair<PrivateKey, Boolean> {
            require(setOf(Base58.Prefix.SecretKey, Base58.Prefix.SecretKeyTestnet, Base58.Prefix.SecretKeySegnet).contains(prefix)) { "invalid base 58 prefix for a private key" }
            val (prefix1, data) = Base58Check.decode(value)
            require(prefix1 == prefix) { "prefix $prefix1 does not match expected prefix $prefix" }
            return Pair(
                PrivateKey(data),
                isCompressed(data)
            )
        }

        @JvmStatic
        public fun fromHex(hex: String): PrivateKey = PrivateKey(Hex.decode(hex))
    }
}