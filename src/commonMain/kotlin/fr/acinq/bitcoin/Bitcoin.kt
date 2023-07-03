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

public sealed class InvalidAddress {
    public object ChainHashMismatch : InvalidAddress()
    public object InvalidBech32Address : InvalidAddress()
    public data class InvalidWitnessVersion(val version: Int) : InvalidAddress()
    public data class GenericError(val error: Throwable) : InvalidAddress()
}

public sealed class InvalidPublicKeyScript {
    public object InvalidChainHash : InvalidPublicKeyScript()
    public object InvalidScript : InvalidPublicKeyScript()
    public data class InvalidWitnessVersion(val version: Int) : InvalidPublicKeyScript()
    public data class GenericError(val error: Throwable) : InvalidPublicKeyScript()
}

public object Bitcoin {
    @JvmStatic
    public fun computeP2PkhAddress(pub: PublicKey, chainHash: ByteVector32): String = pub.p2pkhAddress(chainHash)

    @JvmStatic
    public fun computeBIP44Address(pub: PublicKey, chainHash: ByteVector32): String = computeP2PkhAddress(pub, chainHash)

    /**
     * @param pub public key
     * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
     * @return the p2swh-of-p2pkh address for this key). It is a Base58 address that is compatible with most bitcoin wallets
     */
    @JvmStatic
    public fun computeP2ShOfP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = pub.p2shOfP2wpkhAddress(chainHash)

    @JvmStatic
    public fun computeBIP49Address(pub: PublicKey, chainHash: ByteVector32): String = computeP2ShOfP2WpkhAddress(pub, chainHash)

    /**
     * @param pub public key
     * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
     * @return the BIP84 address for this key (i.e. the p2wpkh address for this key). It is a Bech32 address that will be
     *         understood only by native sewgit wallets
     */
    @JvmStatic
    public fun computeP2WpkhAddress(pub: PublicKey, chainHash: ByteVector32): String = pub.p2wpkhAddress(chainHash)

    @JvmStatic
    public fun computeBIP84Address(pub: PublicKey, chainHash: ByteVector32): String = computeP2WpkhAddress(pub, chainHash)

    @JvmStatic
    public fun addressFromPublicKeyScript(chainHash: ByteVector32, pubkeyScript: List<ScriptElt>): Either<InvalidPublicKeyScript, String> {
        return try {
            when {
                Script.isPay2pkh(pubkeyScript) -> {
                    when (chainHash) {
                        Block.LivenetGenesisBlock.hash -> Either.Right(Base58Check.encode(Base58.Prefix.PubkeyAddress, (pubkeyScript[2] as OP_PUSHDATA).data))
                        Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> Either.Right(Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, (pubkeyScript[2] as OP_PUSHDATA).data))
                        else -> Either.Left(InvalidPublicKeyScript.InvalidChainHash)
                    }
                }

                Script.isPay2sh(pubkeyScript) -> {
                    when (chainHash) {
                        Block.LivenetGenesisBlock.hash -> Either.Right(Base58Check.encode(Base58.Prefix.ScriptAddress, (pubkeyScript[1] as OP_PUSHDATA).data))
                        Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> Either.Right(Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, (pubkeyScript[1] as OP_PUSHDATA).data))
                        else -> Either.Left(InvalidPublicKeyScript.InvalidChainHash)
                    }
                }

                Script.isNativeWitnessScript(pubkeyScript) -> {
                    val hrp = Bech32.hrp(chainHash)
                    val witnessScript = (pubkeyScript[1] as OP_PUSHDATA).data.toByteArray()
                    when (pubkeyScript[0]) {
                        is OP_0 -> when {
                            Script.isPay2wpkh(pubkeyScript) || Script.isPay2wsh(pubkeyScript) -> Either.Right(Bech32.encodeWitnessAddress(hrp, 0, witnessScript))
                            else -> Either.Left(InvalidPublicKeyScript.InvalidScript)
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
                        else -> Either.Left(InvalidPublicKeyScript.InvalidScript)
                    }
                }

                else -> Either.Left(InvalidPublicKeyScript.InvalidScript)
            }
        } catch (e: Exception) {
            Either.Left(InvalidPublicKeyScript.GenericError(e))
        }
    }

    @JvmStatic
    public fun addressFromPublicKeyScript(chainHash: ByteVector32, pubkeyScript: ByteArray): Either<InvalidPublicKeyScript, String> =
        try {
            addressFromPublicKeyScript(chainHash, Script.parse(pubkeyScript))
        } catch (e: Exception) {
            Either.Left(InvalidPublicKeyScript.GenericError(e))
        }

    @JvmStatic
    public fun addressToPublicKeyScript(chainHash: ByteVector32, address: String): Either<InvalidAddress, List<ScriptElt>> {
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

                    else -> Either.Left(InvalidAddress.ChainHashMismatch)
                }
            },
            onFailure = { _ ->
                runCatching { Bech32.decodeWitnessAddress(address) }.fold(
                    onSuccess = {
                        val witnessVersion = witnessVersions[it.second]
                        when {
                            witnessVersion == null -> Either.Left(InvalidAddress.InvalidWitnessVersion(it.second.toInt()))
                            it.third.size != 20 && it.third.size != 32 -> Either.Left(InvalidAddress.InvalidBech32Address)
                            it.first == "bc" && chainHash == Block.LivenetGenesisBlock.hash -> Either.Right(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "tb" && chainHash == Block.TestnetGenesisBlock.hash -> Either.Right(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "tb" && chainHash == Block.SignetGenesisBlock.hash -> Either.Right(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "bcrt" && chainHash == Block.RegtestGenesisBlock.hash -> Either.Right(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            else -> Either.Left(InvalidAddress.ChainHashMismatch)
                        }
                    },
                    onFailure = {
                        Either.Left(InvalidAddress.GenericError(it))
                    }
                )
            }
        )
    }
}