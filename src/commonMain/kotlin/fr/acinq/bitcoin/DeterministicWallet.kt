package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Crypto
import fr.acinq.bitcoin.crypto.PrivateKey
import fr.acinq.bitcoin.crypto.PublicKey
import kotlinx.io.ByteArrayInputStream
import kotlinx.io.ByteArrayOutputStream
import kotlinx.serialization.InternalSerializationApi

/**
 * see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
@ExperimentalStdlibApi
@InternalSerializationApi
object DeterministicWallet {
    const val hardenedKeyIndex = 0x80000000L

    fun hardened(index: Long): Long = hardenedKeyIndex + index

    fun isHardened(index: Long): Boolean = index >= hardenedKeyIndex

    data class KeyPath(val path: List<Long>) {
        constructor(path: String) : this(computePath(path))

        val lastChildNumber = if (path.isEmpty()) 0L else path.last()

        fun derive(number: Long) = KeyPath(path + listOf(number))

        override fun toString() = path.map { KeyPath.childNumberToString(it) }.fold("m"){ a, b -> "$a/$b" }

        companion object {
            val empty = KeyPath(listOf())

            fun computePath(path: String) : List<Long> {
                fun toNumber(value: String): Long = if (value.last() == '\'') hardened(value.dropLast(1).toLong()) else value.toLong()

                val path1 = path.removePrefix("m").removePrefix("/")
                return if (path1.isEmpty())
                    listOf()
                else
                    path1.split('/').map { toNumber(it) }
            }

            fun fromPath(path: String) : KeyPath = KeyPath(path)

            fun childNumberToString(childNumber: Long) = if (isHardened(childNumber)) ((childNumber - hardenedKeyIndex).toString() + "'") else childNumber.toString()
        }
    }

    data class ExtendedPrivateKey(val secretkeybytes: ByteVector32, val chaincode: ByteVector32, val depth: Int, val path: KeyPath, val parent: Long) {

        val privateKey: PrivateKey = PrivateKey(secretkeybytes)

        val publicKey: PublicKey = privateKey.publicKey()
    }

    data class ExtendedPublicKey(val publickeybytes: ByteVector, val chaincode: ByteVector32, val depth: Int, val path: KeyPath, val parent: Long) {
        init {
            require(publickeybytes.size() == 33)
        }
        val publicKey: PublicKey = PublicKey(publickeybytes)
    }

    fun encode(input: ExtendedPrivateKey, testnet: Boolean): String = encode(input, if (testnet) tprv else xprv)

    fun encode(input: ExtendedPrivateKey, prefix: Int): String {
        val out = ByteArrayOutputStream()
        BtcSerializer.writeUInt8(input.depth, out)
        BtcSerializer.writeUInt32BE(input.parent, out)
        BtcSerializer.writeUInt32BE(input.path.lastChildNumber, out)
        out.write(input.chaincode.toByteArray())
        out.write(0)
        out.write(input.secretkeybytes.toByteArray())
        val buffer = out.toByteArray()
        return Base58Check.encode(prefix, buffer )
    }

    fun encode(input: ExtendedPublicKey, testnet: Boolean): String = encode(input, if (testnet) tpub else xpub)

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
    fun generate(seed: ByteVector): ExtendedPrivateKey = generate(seed.toByteArray())
    /**
     *
     * @param input extended private key
     * @return the public key for this private key
     */
    fun publicKey(input: ExtendedPrivateKey): ExtendedPublicKey {
        return ExtendedPublicKey(input.publicKey.value, input.chaincode, depth = input.depth, path = input.path, parent = input.parent)
    }

    /**
     *
     * @param input extended public key
     * @return the fingerprint for this public key
     */
    fun fingerprint(input: ExtendedPublicKey): Long = BtcSerializer.uint32(ByteArrayInputStream(Crypto.hash160(input.publickeybytes).take(4).reversed().toByteArray()))

    /**
     *
     * @param input extended private key
     * @return the fingerprint for this private key (which is based on the corresponding public key)
     */
    fun fingerprint(input: ExtendedPrivateKey): Long = fingerprint(publicKey(input))

    /**
     *
     * @param parent extended private key
     * @param index  index of the child key
     * @return the derived private key at the specified index
     */
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
        return ExtendedPrivateKey(buffer.byteVector32(), chaincode = IR.byteVector32(), depth = parent.depth + 1, path = parent.path.derive(index), parent = fingerprint(parent))
    }

    /**
     *
     * @param parent extended public key
     * @param index  index of the child key
     * @return the derived public key at the specified index
     */
    fun derivePublicKey(parent: ExtendedPublicKey, index: Long): ExtendedPublicKey {
        require(!isHardened(index)) { "Cannot derive public keys from public hardened keys" }

        val I = Crypto.hmac512(parent.chaincode.toByteArray(), parent.publickeybytes.toByteArray() + BtcSerializer.writeUInt32BE(index))
        val IL = I.take(32).toByteArray()
        val IR = I.takeLast(32).toByteArray()
        val p = UInt256(IL)
//        if (p.compareTo(Crypto.curve.n) == 1) {
//            throw RuntimeException("cannot generated child public key")
//        }
        val Ki = PrivateKey(IL).publicKey() + parent.publicKey
//        if (Ki.point.isInfinity) {
//            throw RuntimeException("cannot generated child public key")
//        }
        val buffer = Ki.value
        return ExtendedPublicKey(buffer, chaincode = IR.byteVector32(), depth = parent.depth + 1, path = parent.path.derive(index), parent = fingerprint(parent))
    }

    fun derivePrivateKey(parent: ExtendedPrivateKey, chain: List<Long>): ExtendedPrivateKey = chain.fold(parent, DeterministicWallet::derivePrivateKey)

    fun derivePrivateKey(parent: ExtendedPrivateKey, keyPath: KeyPath): ExtendedPrivateKey = derivePrivateKey(parent, keyPath.path)

    fun derivePrivateKey(parent: ExtendedPrivateKey, keyPath: String): ExtendedPrivateKey = derivePrivateKey(parent, KeyPath.fromPath(keyPath))

    fun derivePublicKey(parent: ExtendedPublicKey, chain: List<Long>): ExtendedPublicKey = chain.fold(parent, DeterministicWallet::derivePublicKey)

    fun derivePublicKey(parent: ExtendedPublicKey, keyPath: KeyPath): ExtendedPublicKey = derivePublicKey(parent, keyPath.path)

    fun derivePublicKey(parent: ExtendedPublicKey, keyPath: String): ExtendedPublicKey = derivePublicKey(parent, KeyPath.fromPath(keyPath))

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