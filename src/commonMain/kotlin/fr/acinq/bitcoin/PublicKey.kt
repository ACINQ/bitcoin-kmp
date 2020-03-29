package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Secp256k1
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

data class PublicKey(@JvmField val value: ByteVector) {
    constructor(data: ByteArray) : this(ByteVector(data))

    operator fun plus(that: PublicKey): PublicKey {
        val pub = Secp256k1.publicKeyAdd(
            value.toByteArray(),
            that.value.toByteArray()
        )
        return PublicKey(
            compress(
                pub
            )
        )
    }

    operator fun times(that: PrivateKey): PublicKey {
        val pub = Secp256k1.publicKeyMul(
            value.toByteArray(),
            that.value.toByteArray()
        )
        return PublicKey(
            compress(
                pub
            )
        )
    }

    /**
     *
     * @return the hash160 of the binary representation of this point. This can be used to generated addresses (the address
     *         of a public key is he base58 encoding of its hash)
     */
    fun hash160(): ByteArray = Crypto.hash160(value.toByteArray())

    override fun toString() = value.toString()

    fun toUncompressedBin(): ByteArray {
        return Secp256k1.parsePublicKey(value.toByteArray())
    }

    init {
        require(Crypto.isPubKeyValid(value.toByteArray()))
    }

    companion object {
        @JvmStatic
        fun compress(pub: ByteArray): ByteArray {
            return if (Crypto.isPubKeyCompressed(pub)) pub else {
                val pub1 = pub.copyOf(33)
                pub1[0] = if (pub.last() % 2 == 0) 2.toByte() else 3.toByte()
                pub1
            }
        }
    }
}