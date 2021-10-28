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
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

/**
 * A bitcoin private key.
 * A private key is valid if it is not 0 and less than the secp256k1 curve order when interpreted as an integer (most significant byte first).
 * The probability of choosing a 32-byte string uniformly at random which is an invalid private key is negligible, so this condition is not checked by default.
 * However, if you receive a private key from an external, untrusted source, you should call `isValid()` before actually using it.
 */
public data class PrivateKey(@JvmField val value: ByteVector32) {
    public constructor(data: ByteArray) : this(
        when {
            data.size == 32 -> ByteVector32(data.copyOf())
            data.size == 33 && data.last() == 1.toByte() -> ByteVector32(data.copyOf(32))
            else -> throw RuntimeException("invalid private key")
        }
    )

    public constructor(data: ByteVector) : this(data.toByteArray())

    /**
     * A private key is valid if it is not 0 and less than the secp256k1 curve order when interpreted as an integer (most significant byte first).
     * The probability of choosing a 32-byte string uniformly at random which is an invalid private key is negligible.
     */
    public fun isValid(): Boolean = Secp256k1.secKeyVerify(value.toByteArray())

    public operator fun plus(that: PrivateKey): PrivateKey =
        PrivateKey(Secp256k1.privKeyTweakAdd(value.toByteArray(), that.value.toByteArray()))

    public operator fun minus(that: PrivateKey): PrivateKey =
        plus(PrivateKey(Secp256k1.privKeyNegate(that.value.toByteArray())))

    public operator fun times(that: PrivateKey): PrivateKey =
        PrivateKey(Secp256k1.privKeyTweakMul(value.toByteArray(), that.value.toByteArray()))

    public fun publicKey(): PublicKey {
        val pub = Secp256k1.pubkeyCreate(value.toByteArray())
        return PublicKey(PublicKey.compress(pub))
    }

    public fun compress(): ByteArray = value.toByteArray() + 1.toByte()

    public fun toBase58(prefix: Byte): String = Base58Check.encode(prefix, compress())

    public fun toHex(): String = Hex.encode(value.toByteArray())

    override fun toString(): String = value.toString()

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
            return Pair(PrivateKey(data), isCompressed(data))
        }

        @JvmStatic
        public fun fromHex(hex: String): PrivateKey = PrivateKey(Hex.decode(hex))
    }
}