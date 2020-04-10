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

import fr.acinq.bitcoin.DeterministicWallet.hardened
import kotlinx.io.ByteArrayInputStream
import kotlinx.io.ByteArrayOutputStream
import kotlinx.serialization.InternalSerializationApi
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
@ExperimentalStdlibApi
@InternalSerializationApi
object DeterministicWallet {
    const val hardenedKeyIndex = 0x80000000L

    @JvmStatic
    fun hardened(index: Long): Long = hardenedKeyIndex + index

    @JvmStatic
    fun isHardened(index: Long): Boolean = index >= hardenedKeyIndex

    data class ExtendedPrivateKey(
        @JvmField val secretkeybytes: ByteVector32,
        @JvmField val chaincode: ByteVector32,
        @JvmField val depth: Int,
        @JvmField val path: KeyPath,
        @JvmField val parent: Long
    ) {
        @JvmField
        val privateKey: PrivateKey = PrivateKey(secretkeybytes)

        @JvmField
        val publicKey: PublicKey = privateKey.publicKey()
    }

    data class ExtendedPublicKey(
        @JvmField val publickeybytes: ByteVector,
        @JvmField val chaincode: ByteVector32,
        @JvmField val depth: Int,
        @JvmField val path: KeyPath,
        @JvmField val parent: Long
    ) {
        init {
            require(publickeybytes.size() == 33)
        }

        @JvmField
        val publicKey: PublicKey = PublicKey(publickeybytes)
    }

    @JvmStatic
    fun encode(input: ExtendedPrivateKey, testnet: Boolean): String = encode(input, if (testnet) tprv else xprv)

    @JvmStatic
    fun encode(input: ExtendedPrivateKey, prefix: Int): String {
        val out = ByteArrayOutputStream()
        BtcSerializer.writeUInt8(input.depth, out)
        BtcSerializer.writeUInt32BE(input.parent, out)
        BtcSerializer.writeUInt32BE(input.path.lastChildNumber, out)
        out.write(input.chaincode.toByteArray())
        out.write(0)
        out.write(input.secretkeybytes.toByteArray())
        val buffer = out.toByteArray()
        return Base58Check.encode(prefix, buffer)
    }

    @JvmStatic
    fun encode(input: ExtendedPublicKey, testnet: Boolean): String = encode(input, if (testnet) tpub else xpub)

    @JvmStatic
    fun encode(input: ExtendedPublicKey, prefix: Int): String {
        val out = ByteArrayOutputStream()
        BtcSerializer.writeUInt8(input.depth, out)
        BtcSerializer.writeUInt32BE(input.parent, out)
        BtcSerializer.writeUInt32BE(input.path.lastChildNumber, out)
        out.write(input.chaincode.toByteArray())
        out.write(input.publickeybytes.toByteArray())
        val buffer = out.toByteArray()
        return Base58Check.encode(prefix, buffer)
    }

    /**
     *
     * @param seed random seed
     * @return a "master" private key
     */
    @JvmStatic
    fun generate(seed: ByteArray): ExtendedPrivateKey {
        val I = Crypto.hmac512("Bitcoin seed".encodeToByteArray(), seed)
        val IL = I.take(32).toByteArray().byteVector32()
        val IR = I.takeLast(32).toByteArray().byteVector32()
        return ExtendedPrivateKey(IL, IR, depth = 0, path = KeyPath.empty, parent = 0L)
    }

    /**
     *
     * @param seed random seed
     * @return a "master" private key
     */
    @JvmStatic
    fun generate(seed: ByteVector): ExtendedPrivateKey = generate(seed.toByteArray())

    /**
     *
     * @param input extended private key
     * @return the public key for this private key
     */
    @JvmStatic
    fun publicKey(input: ExtendedPrivateKey): ExtendedPublicKey {
        return ExtendedPublicKey(
            input.publicKey.value,
            input.chaincode,
            depth = input.depth,
            path = input.path,
            parent = input.parent
        )
    }

    /**
     *
     * @param input extended public key
     * @return the fingerprint for this public key
     */
    @JvmStatic
    fun fingerprint(input: ExtendedPublicKey): Long = BtcSerializer.uint32(
        ByteArrayInputStream(
            Crypto.hash160(input.publickeybytes).take(4).reversed().toByteArray()
        )
    )

    /**
     *
     * @param input extended private key
     * @return the fingerprint for this private key (which is based on the corresponding public key)
     */
    @JvmStatic
    fun fingerprint(input: ExtendedPrivateKey): Long = fingerprint(publicKey(input))

    /**
     *
     * @param parent extended private key
     * @param index  index of the child key
     * @return the derived private key at the specified index
     */
    @JvmStatic
    fun derivePrivateKey(parent: ExtendedPrivateKey, index: Long): ExtendedPrivateKey {
        val I = if (isHardened(index)) {
            val buffer = arrayOf(0.toByte()).toByteArray() + parent.secretkeybytes.toByteArray()
            Crypto.hmac512(parent.chaincode.toByteArray(), buffer + BtcSerializer.writeUInt32BE(index))
        } else {
            val pub = publicKey(parent).publickeybytes
            Crypto.hmac512(parent.chaincode.toByteArray(), pub.toByteArray() + BtcSerializer.writeUInt32BE(index))
        }
        val IL = I.take(32).toByteArray()
        val IR = I.takeLast(32).toByteArray()

        val key = PrivateKey(IL) + parent.privateKey
        val buffer = key.value.toByteArray()
        return ExtendedPrivateKey(
            buffer.byteVector32(),
            chaincode = IR.byteVector32(),
            depth = parent.depth + 1,
            path = parent.path.derive(index),
            parent = fingerprint(parent)
        )
    }

    /**
     *
     * @param parent extended public key
     * @param index  index of the child key
     * @return the derived public key at the specified index
     */
    @ExperimentalUnsignedTypes
    @JvmStatic
    fun derivePublicKey(parent: ExtendedPublicKey, index: Long): ExtendedPublicKey {
        require(!isHardened(index)) { "Cannot derive public keys from public hardened keys" }

        val I = Crypto.hmac512(
            parent.chaincode.toByteArray(),
            parent.publickeybytes.toByteArray() + BtcSerializer.writeUInt32BE(index)
        )
        val IL = I.take(32).toByteArray()
        val IR = I.takeLast(32).toByteArray()

        // TODO: add this check (extremely unlikely)
//        val p = UInt256(IL)
//        if (p.compareTo(Crypto.curve.n) == 1) {
//            throw RuntimeException("cannot generated child public key")
//        }
        val Ki = PrivateKey(IL).publicKey() + parent.publicKey
        // TODO: add this check (extremely unlikely)
//        if (Ki.point.isInfinity) {
//            throw RuntimeException("cannot generated child public key")
//        }
        val buffer = Ki.value
        return ExtendedPublicKey(
            buffer,
            chaincode = IR.byteVector32(),
            depth = parent.depth + 1,
            path = parent.path.derive(index),
            parent = fingerprint(parent)
        )
    }

    @JvmStatic
    fun derivePrivateKey(parent: ExtendedPrivateKey, chain: List<Long>): ExtendedPrivateKey =
        chain.fold(parent, DeterministicWallet::derivePrivateKey)

    @JvmStatic
    fun derivePrivateKey(parent: ExtendedPrivateKey, keyPath: KeyPath): ExtendedPrivateKey =
        derivePrivateKey(parent, keyPath.path)

    @JvmStatic
    fun derivePrivateKey(parent: ExtendedPrivateKey, keyPath: String): ExtendedPrivateKey =
        derivePrivateKey(parent, KeyPath.fromPath(keyPath))

    @ExperimentalUnsignedTypes
    @JvmStatic
    fun derivePublicKey(parent: ExtendedPublicKey, chain: List<Long>): ExtendedPublicKey =
        chain.fold(parent, DeterministicWallet::derivePublicKey)

    @ExperimentalUnsignedTypes
    @JvmStatic
    fun derivePublicKey(parent: ExtendedPublicKey, keyPath: KeyPath): ExtendedPublicKey =
        derivePublicKey(parent, keyPath.path)

    @ExperimentalUnsignedTypes
    @JvmStatic
    fun derivePublicKey(parent: ExtendedPublicKey, keyPath: String): ExtendedPublicKey =
        derivePublicKey(parent, KeyPath.fromPath(keyPath))

    // p2pkh mainnet
    const val xprv = 0x0488ade4
    const val xpub = 0x0488b21e

    // p2sh-of-p2wpkh mainnet
    const val yprv = 0x049d7878
    const val ypub = 0x049d7cb2

    // p2wpkh mainnet
    const val zprv = 0x04b2430c
    const val zpub = 0x04b24746

    // p2pkh testnet
    const val tprv = 0x04358394
    const val tpub = 0x043587cf

    // p2sh-of-p2wpkh testnet
    const val uprv = 0x044a4e28
    const val upub = 0x044a5262

    // p2wpkh testnet
    const val vprv = 0x045f18bc
    const val vpub = 0x045f1cf6
}

@ExperimentalStdlibApi
@InternalSerializationApi
data class KeyPath(@JvmField val path: List<Long>) {
    constructor(path: String) : this(computePath(path))

    @JvmField
    val lastChildNumber = if (path.isEmpty()) 0L else path.last()

    fun derive(number: Long) = KeyPath(path + listOf(number))

    fun append(index: Long): KeyPath {
        return KeyPath(path + listOf(index))
    }

    fun append(indexes: List<Long>): KeyPath {
        return KeyPath(path + indexes)
    }

    fun append(that: KeyPath): KeyPath {
        return KeyPath(path + that.path)
    }

    override fun toString() = path.map { KeyPath.childNumberToString(it) }.fold("m") { a, b -> "$a/$b" }

    @InternalSerializationApi
    @ExperimentalStdlibApi
    companion object {
        val empty = KeyPath(listOf())

        @JvmStatic
        fun computePath(path: String): List<Long> {
            fun toNumber(value: String): Long = if (value.last() == '\'') hardened(value.dropLast(1).toLong()) else value.toLong()

            val path1 = path.removePrefix("m").removePrefix("/")
            return if (path1.isEmpty())
                listOf()
            else
                path1.split('/').map { toNumber(it) }
        }

        @JvmStatic
        fun fromPath(path: String): KeyPath = KeyPath(path)

        fun childNumberToString(childNumber: Long) =
            if (DeterministicWallet.isHardened(childNumber)) ((childNumber - DeterministicWallet.hardenedKeyIndex).toString() + "'") else childNumber.toString()
    }
}