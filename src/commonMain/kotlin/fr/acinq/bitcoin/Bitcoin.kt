package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Crypto
import fr.acinq.bitcoin.crypto.PublicKey
import kotlinx.serialization.InternalSerializationApi

fun fixSize(data: ByteArray, size: Int): ByteArray = when {
    data.size == size -> data
    data.size < size -> ByteArray(size - data.size) + data
    else -> {
        throw RuntimeException("overflow")
    }
}

fun <T> List<T>.updated(i: Int, t: T): List<T> = when (i) {
    0 -> listOf(t) + this.drop(1)
    this.lastIndex -> this.dropLast(1) + t
    else -> this.take(i) + t + this.take(this.size - i - 1)
}

fun <T> `???`(): T {
    throw RuntimeException("not implemented")
}

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
@InternalSerializationApi
fun computeP2PkhAddress(pub: PublicKey, chainHash: ByteVector32): String {
    val hash = pub.hash160()
    return when (chainHash) {
        Block.RegtestGenesisBlock.hash, Block.TestnetGenesisBlock.hash -> Base58Check.encode(
            Base58.Prefix.PubkeyAddressTestnet,
            hash
        )
        Block.LivenetGenesisBlock.hash -> Base58Check.encode(Base58.Prefix.PubkeyAddress, hash)
        else -> throw IllegalArgumentException("Unknown chain hash: $chainHash")
    }
}

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
@InternalSerializationApi
fun computeBIP44Address(pub: PublicKey, chainHash: ByteVector32) = computeP2PkhAddress(pub, chainHash)

/**
 *
 * @param pub       public key
 * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
 * @return the p2swh-of-p2pkh address for this key). It is a Base58 address that is compatible with most bitcoin wallets
 */
@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
@InternalSerializationApi
fun computeP2ShOfP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String {
    val script = Script.pay2wpkh(pub)
    val hash = Crypto.hash160(Script.write(script))
    return when (chainHash) {
        Block.RegtestGenesisBlock.hash, Block.TestnetGenesisBlock.hash -> Base58Check.encode(
            Base58.Prefix.ScriptAddressTestnet,
            hash
        )
        Block.LivenetGenesisBlock.hash -> Base58Check.encode(Base58.Prefix.ScriptAddress, hash)
        else -> throw IllegalArgumentException("Unknown chain hash: $chainHash")
    }
}

@ExperimentalUnsignedTypes
@InternalSerializationApi
@ExperimentalStdlibApi
fun computeBIP49Address(pub: PublicKey, chainHash: ByteVector32) = computeP2ShOfP2WpkhAddress(pub, chainHash)

/**
 *
 * @param pub       public key
 * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
 * @return the BIP84 address for this key (i.e. the p2wpkh address for this key). It is a Bech32 address that will be
 *         understood only by native sewgit wallets
 */
@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
@InternalSerializationApi
fun computeP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String {
    val hrp = when (chainHash) {
        Block.LivenetGenesisBlock.hash -> "bc"
        Block.TestnetGenesisBlock.hash -> "tb"
        Block.RegtestGenesisBlock.hash -> "bcrt"
        else -> throw IllegalArgumentException("Unknown chain hash: $chainHash")
    }
    val hash = pub.hash160()
    return Bech32.encodeWitnessAddress(hrp, 0, hash)
}

@ExperimentalUnsignedTypes
@InternalSerializationApi
@ExperimentalStdlibApi
fun computeBIP84Address(pub: PublicKey, chainHash: ByteVector32) = computeP2WpkhAddress(pub, chainHash)
