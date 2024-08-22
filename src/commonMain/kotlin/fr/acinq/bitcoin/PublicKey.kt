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
 * A bitcoin public key (in compressed form).
 * A public key is valid if it represents a point on the secp256k1 curve.
 * The validity of this public key is not checked by default, because when you create a public key from a private key it will always be valid.
 * However, if you receive a public key from an external, untrusted source, you should call `isValid()` before actually using it.
 */
public data class PublicKey(@JvmField val value: ByteVector) {
    public constructor(data: ByteArray) : this(ByteVector(data))

    init {
        require(value.size() == 33) { "public key must be in compressed form" }
    }

    /**
     * A public key is valid if it represents a point on the secp256k1 curve.
     */
    public fun isValid(): Boolean = Crypto.isPubKeyValid(value.toByteArray())

    public fun isEven(): Boolean = (value[0] == 2.toByte())

    public fun isOdd(): Boolean = !isEven()

    public fun xOnly(): XonlyPublicKey = XonlyPublicKey(this)

    public operator fun plus(that: PublicKey): PublicKey {
        val pub = Secp256k1.pubKeyCombine(arrayOf(value.toByteArray(), that.value.toByteArray()))
        return PublicKey(compress(pub))
    }

    public operator fun unaryMinus(): PublicKey {
        val pub = Secp256k1.pubKeyNegate(value.toByteArray())
        return PublicKey(compress(pub))
    }

    public operator fun minus(that: PublicKey): PublicKey = plus(-that)

    public operator fun times(that: PrivateKey): PublicKey {
        val pub = Secp256k1.pubKeyTweakMul(value.toByteArray(), that.value.toByteArray())
        return PublicKey(compress(pub))
    }

    /**
     * @return the hash160 of the compressed binary representation of this point.
     */
    public fun hash160(): ByteArray = Crypto.hash160(value.toByteArray())

    /**
     * @return the uncompressed public key, which can be used for legacy addresses.
     */
    public fun toUncompressedBin(): ByteArray = Secp256k1.pubkeyParse(value.toByteArray())

    /**
     * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
     * @return the "legacy" p2pkh address for this key
     */
    public fun p2pkhAddress(chainHash: BlockHash): String = when (chainHash) {
        Block.Testnet4GenesisBlock.hash, Block.Testnet3GenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, hash160())
        Block.LivenetGenesisBlock.hash -> Base58Check.encode(Base58.Prefix.PubkeyAddress, hash160())
        else -> error("invalid chain hash $chainHash")
    }

    /**
     * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
     * @return the p2swh-of-p2pkh address for this key.
     * It is a Base58 address that is compatible with most bitcoin wallets.
     */
    public fun p2shOfP2wpkhAddress(chainHash: BlockHash): String {
        val script = Script.pay2wpkh(this)
        val hash = Crypto.hash160(Script.write(script))
        return when (chainHash) {
            Block.Testnet4GenesisBlock.hash, Block.Testnet3GenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, hash)
            Block.LivenetGenesisBlock.hash -> Base58Check.encode(Base58.Prefix.ScriptAddress, hash)
            else -> error("invalid chain hash $chainHash")
        }
    }

    /**
     * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
     * @return the BIP84 address for this key (i.e. the p2wpkh address for this key).
     * It is a Bech32 address that will be understood only by native segwit wallets.
     */
    public fun p2wpkhAddress(chainHash: BlockHash): String {
        return Bech32.encodeWitnessAddress(Bech32.hrp(chainHash), 0, hash160())
    }

    /**
     * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
     * @return the BIP86 address for this key (i.e. the p2tr address for this key with an explicit absence of scripts).
     */
    public fun p2trAddress(chainHash: BlockHash): String = xOnly().p2trAddress(chainHash)

    public fun toHex(): String = value.toHex()

    override fun toString(): String = value.toString()

    public companion object {
        @JvmField
        public val Generator: PublicKey = parse(Hex.decode("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))

        @JvmStatic
        public fun parse(pub: ByteArray): PublicKey = PublicKey(compress(pub))

        @JvmStatic
        public fun compress(pub: ByteArray): ByteArray = when {
            Crypto.isPubKeyCompressed(pub) -> pub
            else -> {
                val compressed = pub.copyOf(33)
                compressed[0] = if (pub.last() % 2 == 0) 2.toByte() else 3.toByte()
                compressed
            }
        }

        @JvmStatic
        public fun fromHex(hex: String): PublicKey = PublicKey(Hex.decode(hex))
    }
}