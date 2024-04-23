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

import fr.acinq.bitcoin.utils.Either
import kotlin.jvm.JvmStatic

public const val MaxBlockSize: Int = 1000000

public fun <T> List<T>.updated(i: Int, t: T): List<T> = when (i) {
    0 -> listOf(t) + this.drop(1)
    this.lastIndex -> this.dropLast(1) + t
    else -> this.take(i) + t + this.drop(i + 1)
}

public sealed class BitcoinError {
    public abstract val message: String
    public abstract val cause: Throwable?
    override fun toString(): String = when (cause) {
        null -> message
        else -> "$message: ${cause?.message}"
    }

    public data object InvalidChainHash : BitcoinError() {
        override val message: String = "invalid chain hash"
        override val cause: Throwable? = null
    }

    public data object ChainHashMismatch : BitcoinError() {
        override val message: String = "chain hash mismatch"
        override val cause: Throwable? = null
    }

    public data object InvalidScript : BitcoinError() {
        override val message: String = "invalid script"
        override val cause: Throwable? = null
    }

    public data object InvalidAddress : BitcoinError() {
        override val message: String = "invalid address"
        override val cause: Throwable? = null
    }

    public data object InvalidBech32Address : BitcoinError() {
        override val message: String = "invalid bech32 address"
        override val cause: Throwable? = null
    }

    public data class InvalidWitnessVersion(val version: Int) : BitcoinError() {
        override val message: String = "invalid witness version $version"
        override val cause: Throwable? = null
    }

    public data class GenericError(override val message: String, override val cause: Throwable?) : BitcoinError()
}

public object Bitcoin {
    @JvmStatic
    public fun computeP2PkhAddress(pub: PublicKey, chainHash: BlockHash): String = pub.p2pkhAddress(chainHash)

    @JvmStatic
    public fun computeBIP44Address(pub: PublicKey, chainHash: BlockHash): String = computeP2PkhAddress(pub, chainHash)

    /**
     * @param pub public key
     * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
     * @return the p2swh-of-p2pkh address for this key. It is a Base58 address that is compatible with most bitcoin wallets
     */
    @JvmStatic
    public fun computeP2ShOfP2WpkhAddress(pub: PublicKey, chainHash: BlockHash): String = pub.p2shOfP2wpkhAddress(chainHash)

    @JvmStatic
    public fun computeBIP49Address(pub: PublicKey, chainHash: BlockHash): String = computeP2ShOfP2WpkhAddress(pub, chainHash)

    /**
     * @param pub public key
     * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
     * @return the BIP84 address for this key (i.e. the p2wpkh address for this key). It is a Bech32 address that will be
     *         understood only by native segwit wallets
     */
    @JvmStatic
    public fun computeP2WpkhAddress(pub: PublicKey, chainHash: BlockHash): String = pub.p2wpkhAddress(chainHash)

    @JvmStatic
    public fun computeBIP84Address(pub: PublicKey, chainHash: BlockHash): String = computeP2WpkhAddress(pub, chainHash)

    @JvmStatic
    public fun computeBIP86Address(pub: PublicKey, chainHash: BlockHash): String = pub.p2trAddress(chainHash)

    @JvmStatic
    public fun computeBIP86Address(pub: XonlyPublicKey, chainHash: BlockHash): String = pub.p2trAddress(chainHash)

    /**
     * Compute an address from a public key script
     * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
     * @param pubkeyScript public key script
     */
    @JvmStatic
    public fun addressFromPublicKeyScript(chainHash: BlockHash, pubkeyScript: List<ScriptElt>): Either<BitcoinError, String> {
        try {
            return when {
                Script.isPay2pkh(pubkeyScript) -> {
                    val prefix = when (chainHash) {
                        Block.LivenetGenesisBlock.hash -> Base58.Prefix.PubkeyAddress
                        Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> Base58.Prefix.PubkeyAddressTestnet
                        else -> return Either.Left(BitcoinError.InvalidChainHash)
                    }
                    Either.Right(Base58Check.encode(prefix, (pubkeyScript[2] as OP_PUSHDATA).data))
                }

                Script.isPay2sh(pubkeyScript) -> {
                    val prefix = when (chainHash) {
                        Block.LivenetGenesisBlock.hash -> Base58.Prefix.ScriptAddress
                        Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> Base58.Prefix.ScriptAddressTestnet
                        else -> return Either.Left(BitcoinError.InvalidChainHash)
                    }
                    Either.Right(Base58Check.encode(prefix, (pubkeyScript[1] as OP_PUSHDATA).data))
                }

                Script.isNativeWitnessScript(pubkeyScript) -> {
                    val hrp = Bech32.hrp(chainHash)
                    val witnessScript = (pubkeyScript[1] as OP_PUSHDATA).data.toByteArray()
                    when (pubkeyScript[0]) {
                        is OP_0 -> when {
                            Script.isPay2wpkh(pubkeyScript) || Script.isPay2wsh(pubkeyScript) -> Either.Right(Bech32.encodeWitnessAddress(hrp, 0, witnessScript))
                            else -> return Either.Left(BitcoinError.InvalidScript)
                        }

                        is OP_1 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 1, witnessScript))
                        is OP_2 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 2, witnessScript))
                        is OP_3 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 3, witnessScript))
                        is OP_4 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 4, witnessScript))
                        is OP_5 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 5, witnessScript))
                        is OP_6 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 6, witnessScript))
                        is OP_7 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 7, witnessScript))
                        is OP_8 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 8, witnessScript))
                        is OP_9 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 9, witnessScript))
                        is OP_10 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 10, witnessScript))
                        is OP_11 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 11, witnessScript))
                        is OP_12 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 12, witnessScript))
                        is OP_13 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 13, witnessScript))
                        is OP_14 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 14, witnessScript))
                        is OP_15 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 15, witnessScript))
                        is OP_16 -> Either.Right(Bech32.encodeWitnessAddress(hrp, 16, witnessScript))
                        else -> return Either.Left(BitcoinError.InvalidScript)
                    }
                }

                else -> return Either.Left(BitcoinError.InvalidScript)
            }
        } catch (t: Throwable) {
            return Either.Left(BitcoinError.GenericError("", t))
        }
    }

    @JvmStatic
    public fun addressFromPublicKeyScript(chainHash: BlockHash, pubkeyScript: ByteArray): Either<BitcoinError, String> {
        return runCatching { Script.parse(pubkeyScript) }.fold(
            onSuccess = {
                addressFromPublicKeyScript(chainHash, it)
            },
            onFailure = {
                Either.Left(BitcoinError.InvalidScript)
            }
        )
    }

    @JvmStatic
    public fun addressToPublicKeyScript(chainHash: BlockHash, address: String): Either<BitcoinError, List<ScriptElt>> {
        val witnessVersions = mapOf(
            0.toByte() to OP_0,
            1.toByte() to OP_1,
            2.toByte() to OP_2,
            3.toByte() to OP_3,
            4.toByte() to OP_4,
            5.toByte() to OP_5,
            6.toByte() to OP_6,
            7.toByte() to OP_7,
            8.toByte() to OP_8,
            9.toByte() to OP_9,
            10.toByte() to OP_10,
            11.toByte() to OP_11,
            12.toByte() to OP_12,
            13.toByte() to OP_13,
            14.toByte() to OP_14,
            15.toByte() to OP_15,
            16.toByte() to OP_16
        )

        return runCatching { Base58Check.decode(address) }.fold(
            onSuccess = {
                when {
                    it.first == Base58.Prefix.PubkeyAddressTestnet && (chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash || chainHash == Block.SignetGenesisBlock.hash) ->
                        Either.Right(Script.pay2pkh(it.second))

                    it.first == Base58.Prefix.PubkeyAddress && chainHash == Block.LivenetGenesisBlock.hash ->
                        Either.Right(Script.pay2pkh(it.second))

                    it.first == Base58.Prefix.ScriptAddressTestnet && (chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash || chainHash == Block.SignetGenesisBlock.hash) ->
                        Either.Right(listOf(OP_HASH160, OP_PUSHDATA(it.second), OP_EQUAL))

                    it.first == Base58.Prefix.ScriptAddress && chainHash == Block.LivenetGenesisBlock.hash ->
                        Either.Right(listOf(OP_HASH160, OP_PUSHDATA(it.second), OP_EQUAL))

                    else -> Either.Left(BitcoinError.ChainHashMismatch)
                }
            },
            onFailure = { _ ->
                runCatching { Bech32.decodeWitnessAddress(address) }.fold(
                    onSuccess = {
                        val witnessVersion = witnessVersions[it.second]
                        when {
                            witnessVersion == null -> Either.Left(BitcoinError.InvalidWitnessVersion(it.second.toInt()))
                            it.third.size != 20 && it.third.size != 32 -> Either.Left(BitcoinError.InvalidBech32Address)
                            it.first == "bc" && chainHash == Block.LivenetGenesisBlock.hash -> Either.Right(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "tb" && chainHash == Block.TestnetGenesisBlock.hash -> Either.Right(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "tb" && chainHash == Block.SignetGenesisBlock.hash -> Either.Right(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "bcrt" && chainHash == Block.RegtestGenesisBlock.hash -> Either.Right(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            else -> Either.Left(BitcoinError.ChainHashMismatch)
                        }
                    },
                    onFailure = {
                        Either.Left(BitcoinError.InvalidAddress)
                    }
                )
            }
        )
    }
}

public sealed class Chain(public val name: String, private val genesis: Block) {
    public object Regtest : Chain("Regtest", Block.RegtestGenesisBlock)
    public object Testnet : Chain("Testnet", Block.TestnetGenesisBlock)
    public object Signet : Chain("Signet", Block.SignetGenesisBlock)
    public object Mainnet : Chain("Mainnet", Block.LivenetGenesisBlock)

    public fun isMainnet(): Boolean = this is Mainnet
    public fun isTestnet(): Boolean = this is Testnet

    public val chainHash: BlockHash get() = genesis.hash

    override fun toString(): String = name
}