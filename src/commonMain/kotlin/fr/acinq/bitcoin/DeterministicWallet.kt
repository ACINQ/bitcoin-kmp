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
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Output
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
@OptIn(ExperimentalUnsignedTypes::class)
public object DeterministicWallet {
    public const val hardenedKeyIndex: Long = 0x80000000L

    @JvmStatic
    public fun hardened(index: Long): Long = hardenedKeyIndex + index

    @JvmStatic
    public fun isHardened(index: Long): Boolean = index >= hardenedKeyIndex

    public data class ExtendedPrivateKey(
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

        public companion object {
            @JvmStatic
            public fun decode(input: String, parentPath: KeyPath = KeyPath.empty): Pair<Int, ExtendedPrivateKey> {
                val (prefix, bin) = Base58Check.decodeWithIntPrefix(input)
                val bis = ByteArrayInput(bin)
                val depth = bis.read()
                val parent = Pack.int32BE(bis).toLong() and 0xffffffffL
                val childNumber = Pack.int32BE(bis).toLong() and 0xffffffffL
                val chaincode = ByteArray(32)
                bis.read(chaincode, 0)
                require(bis.read() == 0)
                val secretkeybytes = ByteArray(32)
                bis.read(secretkeybytes, 0)
                return Pair(prefix, ExtendedPrivateKey(secretkeybytes.byteVector32(), chaincode.byteVector32(), depth, parentPath.derive(childNumber), parent))
            }
        }
    }

    public data class ExtendedPublicKey(
        @JvmField val publickeybytes: ByteVector,
        @JvmField val chaincode: ByteVector32,
        @JvmField val depth: Int,
        @JvmField val path: KeyPath,
        @JvmField val parent: Long
    ) {
        init {
            require(publickeybytes.size() == 33)
        }

        val publicKey: PublicKey get() = PublicKey(publickeybytes)

        public companion object {
            @JvmStatic
            public fun decode(input: String, parentPath: KeyPath = KeyPath.empty): Pair<Int, ExtendedPublicKey> {
                val (prefix, bin) = Base58Check.decodeWithIntPrefix(input)
                val bis = ByteArrayInput(bin)
                val depth = bis.read()
                val parent = Pack.int32BE(bis).toLong() and 0xffffffffL
                val childNumber = Pack.int32BE(bis).toLong() and 0xffffffffL
                val chaincode = ByteArray(32)
                bis.read(chaincode, 0)
                val publickeybytes = ByteArray(33)
                bis.read(publickeybytes, 0)
                return Pair(prefix, ExtendedPublicKey(publickeybytes.byteVector(), chaincode.byteVector32(), depth, parentPath.derive(childNumber), parent))
            }
        }
    }

    @JvmStatic
    public fun encode(input: ExtendedPrivateKey, testnet: Boolean): String = encode(input, if (testnet) tprv else xprv)

    @JvmStatic
    public fun encode(input: ExtendedPrivateKey, prefix: Int): String {
        val out = ByteArrayOutput()
        out.write(input.depth)
        Pack.writeInt32BE(input.parent.toInt(), out)
        Pack.writeInt32BE(input.path.lastChildNumber.toInt(), out)
        out.write(input.chaincode.toByteArray())
        out.write(0)
        out.write(input.secretkeybytes.toByteArray())
        val buffer = out.toByteArray()
        return Base58Check.encode(prefix, buffer)
    }

    @JvmStatic
    public fun encode(input: ExtendedPublicKey, testnet: Boolean): String = encode(input, if (testnet) tpub else xpub)

    @JvmStatic
    public fun encode(input: ExtendedPublicKey, prefix: Int): String {
        val out = ByteArrayOutput()
        write(input, out)
        val buffer = out.toByteArray()
        return Base58Check.encode(prefix, buffer)
    }

    @JvmStatic
    public fun write(input: ExtendedPublicKey, out: Output) {
        out.write(input.depth)
        Pack.writeInt32BE(input.parent.toInt(), out)
        Pack.writeInt32BE(input.path.lastChildNumber.toInt(), out)
        out.write(input.chaincode.toByteArray())
        out.write(input.publickeybytes.toByteArray())
    }

    /**
     *
     * @param seed random seed
     * @return a "master" private key
     */
    @JvmStatic
    @OptIn(ExperimentalStdlibApi::class)
    public fun generate(seed: ByteArray): ExtendedPrivateKey {
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
    public fun generate(seed: ByteVector): ExtendedPrivateKey = generate(seed.toByteArray())

    /**
     *
     * @param input extended private key
     * @return the public key for this private key
     */
    @JvmStatic
    public fun publicKey(input: ExtendedPrivateKey): ExtendedPublicKey {
        return ExtendedPublicKey(input.publicKey.value, input.chaincode, depth = input.depth, path = input.path, parent = input.parent)
    }

    /**
     *
     * @param input extended public key
     * @return the fingerprint for this public key
     */
    @JvmStatic
    public fun fingerprint(input: ExtendedPublicKey): Long = Pack.int32LE(ByteArrayInput(Crypto.hash160(input.publickeybytes).take(4).reversed().toByteArray())).toLong()

    /**
     *
     * @param input extended private key
     * @return the fingerprint for this private key (which is based on the corresponding public key)
     */
    @JvmStatic
    public fun fingerprint(input: ExtendedPrivateKey): Long = fingerprint(publicKey(input))

    /**
     *
     * @param parent extended private key
     * @param index  index of the child key
     * @return the derived private key at the specified index
     */
    @JvmStatic
    public fun derivePrivateKey(parent: ExtendedPrivateKey, index: Long): ExtendedPrivateKey {
        val I = if (isHardened(index)) {
            val buffer = arrayOf(0.toByte()).toByteArray() + parent.secretkeybytes.toByteArray()
            Crypto.hmac512(parent.chaincode.toByteArray(), buffer + Pack.writeInt32BE(index.toInt()))
        } else {
            val pub = publicKey(parent).publickeybytes
            Crypto.hmac512(parent.chaincode.toByteArray(), pub.toByteArray() + Pack.writeInt32BE(index.toInt()))
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
    @JvmStatic
    public fun derivePublicKey(parent: ExtendedPublicKey, index: Long): ExtendedPublicKey {
        require(!isHardened(index)) { "Cannot derive public keys from public hardened keys" }

        val I = Crypto.hmac512(
            parent.chaincode.toByteArray(),
            parent.publickeybytes.toByteArray() + Pack.writeInt32BE(index.toInt())
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
    public fun derivePrivateKey(parent: ExtendedPrivateKey, chain: List<Long>): ExtendedPrivateKey =
        chain.fold(parent, DeterministicWallet::derivePrivateKey)

    @JvmStatic
    public fun derivePrivateKey(parent: ExtendedPrivateKey, keyPath: KeyPath): ExtendedPrivateKey =
        derivePrivateKey(parent, keyPath.path)

    @JvmStatic
    public fun derivePrivateKey(parent: ExtendedPrivateKey, keyPath: String): ExtendedPrivateKey =
        derivePrivateKey(parent, KeyPath.fromPath(keyPath))

    @JvmStatic
    public fun derivePublicKey(parent: ExtendedPublicKey, chain: List<Long>): ExtendedPublicKey =
        chain.fold(parent, DeterministicWallet::derivePublicKey)

    @JvmStatic
    public fun derivePublicKey(parent: ExtendedPublicKey, keyPath: KeyPath): ExtendedPublicKey =
        derivePublicKey(parent, keyPath.path)

    @JvmStatic
    public fun derivePublicKey(parent: ExtendedPublicKey, keyPath: String): ExtendedPublicKey =
        derivePublicKey(parent, KeyPath.fromPath(keyPath))

    // p2pkh mainnet
    public const val xprv: Int = 0x0488ade4
    public const val xpub: Int = 0x0488b21e

    // p2sh-of-p2wpkh mainnet
    public const val yprv: Int = 0x049d7878
    public const val ypub: Int = 0x049d7cb2

    // p2wpkh mainnet
    public const val zprv: Int = 0x04b2430c
    public const val zpub: Int = 0x04b24746

    // p2pkh testnet
    public const val tprv: Int = 0x04358394
    public const val tpub: Int = 0x043587cf

    // p2sh-of-p2wpkh testnet
    public const val uprv: Int = 0x044a4e28
    public const val upub: Int = 0x044a5262

    // p2wpkh testnet
    public const val vprv: Int = 0x045f18bc
    public const val vpub: Int = 0x045f1cf6
}

public data class KeyPath(@JvmField val path: List<Long>) {
    public constructor(path: String) : this(computePath(path))

    public val lastChildNumber: Long get() = if (path.isEmpty()) 0L else path.last()

    public fun derive(number: Long): KeyPath = KeyPath(path + listOf(number))

    public fun append(index: Long): KeyPath {
        return KeyPath(path + listOf(index))
    }

    public fun append(indexes: List<Long>): KeyPath {
        return KeyPath(path + indexes)
    }

    public fun append(that: KeyPath): KeyPath {
        return KeyPath(path + that.path)
    }

    override fun toString(): String = path.map { childNumberToString(it) }.fold("m") { a, b -> "$a/$b" }

    public companion object {
        public val empty: KeyPath = KeyPath(listOf())

        @JvmStatic
        public fun computePath(path: String): List<Long> {
            fun toNumber(value: String): Long = if (value.last() == '\'') hardened(value.dropLast(1).toLong()) else value.toLong()

            val path1 = path.removePrefix("m").removePrefix("/")
            return if (path1.isEmpty())
                listOf()
            else
                path1.split('/').map { toNumber(it) }
        }

        @JvmStatic
        public fun fromPath(path: String): KeyPath = KeyPath(path)

        public fun childNumberToString(childNumber: Long): String =
            if (DeterministicWallet.isHardened(childNumber)) ((childNumber - DeterministicWallet.hardenedKeyIndex).toString() + "'") else childNumber.toString()
    }
}