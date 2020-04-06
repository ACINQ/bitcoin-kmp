package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Secp256k1
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

data class PrivateKey(@JvmField val value: ByteVector32) {
    constructor(data: ByteArray) : this(
        when {
            data.size == 32 -> ByteVector32(data.copyOf())
            data.size == 33 && data.last() == 1.toByte() -> ByteVector32(data.copyOf(32))
            else -> throw RuntimeException("invalid private key")
        }
    )

    constructor(data: ByteVector) : this(data.toByteArray())

    operator fun plus(that: PrivateKey): PrivateKey =
        PrivateKey(
            Secp256k1.privateKeyAdd(
                value.toByteArray(),
                that.value.toByteArray()
            )
        )

    operator fun minus(that: PrivateKey): PrivateKey =
        plus(
            PrivateKey(
                Secp256k1.privateKeyNegate(
                    that.value.toByteArray()
                )
            )
        )

    operator fun times(that: PrivateKey): PrivateKey =
        PrivateKey(
            Secp256k1.privateKeyMul(
                value.toByteArray(),
                that.value.toByteArray()
            )
        )

    fun publicKey(): PublicKey {
        val pub = Secp256k1.computePublicKey(value.toByteArray())
        return PublicKey(
            PublicKey.compress(
                pub
            )
        )
    }

    fun toBase58(prefix: Byte) = Base58Check.encode(prefix, value.toByteArray() + 1.toByte())

    companion object {
        @JvmStatic
        fun isCompressed(data: ByteArray): Boolean {
            return when {
                data.size == 32 -> false
                data.size == 33 && data.last() == 1.toByte() -> true
                else -> throw IllegalArgumentException("invalid private key ${Hex.encode(data)}")
            }
        }

        @JvmStatic
        fun fromBase58(value: String, prefix: Byte): Pair<PrivateKey, Boolean> {
            require(
                setOf(
                    Base58.Prefix.SecretKey,
                    Base58.Prefix.SecretKeyTestnet,
                    Base58.Prefix.SecretKeySegnet
                ).contains(prefix)
            ) { "invalid base 58 prefix for a private key" }
            val (prefix1, data) = Base58Check.decode(value)
            require(prefix1 == prefix) { "prefix $prefix1 does not match expected prefix $prefix" }
            return Pair(
                PrivateKey(data),
                isCompressed(data)
            )
        }

        @JvmStatic
        fun fromHex(hex: String) = PrivateKey(Hex.decode(hex))
    }
}