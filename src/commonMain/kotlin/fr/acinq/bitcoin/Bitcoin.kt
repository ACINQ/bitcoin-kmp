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

import kotlin.jvm.JvmStatic

public const val MaxBlockSize: Int = 1000000

public fun <T> List<T>.updated(i: Int, t: T): List<T> = when (i) {
    0 -> listOf(t) + this.drop(1)
    this.lastIndex -> this.dropLast(1) + t
    else -> this.take(i) + t + this.drop(i + 1)
}

public sealed class AddressToPublicKeyScriptResult {

    public abstract val result: List<ScriptElt>?

    public val isSuccess: Boolean = result != null

    public val isFailure: Boolean = !isSuccess

    public data class Success(val script: List<ScriptElt>) : AddressToPublicKeyScriptResult() {
        override val result: List<ScriptElt>? = script
    }

    public sealed class Failure : AddressToPublicKeyScriptResult() {
        override val result: List<ScriptElt>? = null

        public object ChainHashMismatch : Failure() {
            override fun toString(): String = "chain hash mismatch"
        }

        public object InvalidAddress : Failure() {
            override fun toString(): String = "invalid base58 or bech32 address "
        }

        public object InvalidBech32Address : Failure() {
            override fun toString(): String = "invalid bech32 address"
        }

        public data class InvalidWitnessVersion(val version: Int) : Failure() {
            override fun toString(): String = "invalid witness version $version"
        }
    }
}

public sealed class AddressFromPublicKeyScriptResult {
    public abstract val result: String?
    public val isSuccess: Boolean = result != null
    public val isFailure: Boolean = !isSuccess

    public data class Success(val address: String) : AddressFromPublicKeyScriptResult() {
        override val result: String? = address
    }

    public sealed class Failure : AddressFromPublicKeyScriptResult() {
        override val result: String? = null

        public object InvalidChainHash : Failure() {
            override fun toString(): String = "invalid chain hash"
        }

        public object InvalidScript : Failure() {
            override fun toString(): String = "invalid script"
        }

        public data class GenericError(val t: Throwable) : Failure() {
            override fun toString(): String = "generic failure: ${t.message}"
        }
    }
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

    /**
     * Compute an address from a public key script
     * @param chainHash chain hash (i.e. hash of the genesic block of the chain we're on)
     * @param pubkeyScript public key script
     */
    @JvmStatic
    public fun addressFromPublicKeyScript(chainHash: ByteVector32, pubkeyScript: List<ScriptElt>): AddressFromPublicKeyScriptResult {
        try {
            return when {
                Script.isPay2pkh(pubkeyScript) -> {
                    val prefix = when (chainHash) {
                        Block.LivenetGenesisBlock.hash -> Base58.Prefix.PubkeyAddress
                        Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> Base58.Prefix.PubkeyAddressTestnet
                        else -> return AddressFromPublicKeyScriptResult.Failure.InvalidChainHash
                    }
                    AddressFromPublicKeyScriptResult.Success(Base58Check.encode(prefix, (pubkeyScript[2] as OP_PUSHDATA).data))
                }

                Script.isPay2sh(pubkeyScript) -> {
                    val prefix = when (chainHash) {
                        Block.LivenetGenesisBlock.hash -> Base58.Prefix.ScriptAddress
                        Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> Base58.Prefix.ScriptAddressTestnet
                        else -> return AddressFromPublicKeyScriptResult.Failure.InvalidChainHash
                    }
                    AddressFromPublicKeyScriptResult.Success(Base58Check.encode(prefix, (pubkeyScript[1] as OP_PUSHDATA).data))
                }

                Script.isNativeWitnessScript(pubkeyScript) -> {
                    val hrp = Bech32.hrp(chainHash)
                    val witnessScript = (pubkeyScript[1] as OP_PUSHDATA).data.toByteArray()
                    when (pubkeyScript[0]) {
                        is OP_0 -> when {
                            Script.isPay2wpkh(pubkeyScript) || Script.isPay2wsh(pubkeyScript) -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 0, witnessScript))
                            else -> AddressFromPublicKeyScriptResult.Failure.InvalidScript
                        }

                        is OP_1 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 1, witnessScript))
                        is OP_2 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 2, witnessScript))
                        is OP_3 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 3, witnessScript))
                        is OP_4 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 4, witnessScript))
                        is OP_5 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 5, witnessScript))
                        is OP_6 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 6, witnessScript))
                        is OP_7 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 7, witnessScript))
                        is OP_8 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 8, witnessScript))
                        is OP_9 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 9, witnessScript))
                        is OP_10 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 10, witnessScript))
                        is OP_11 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 11, witnessScript))
                        is OP_12 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 12, witnessScript))
                        is OP_13 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 13, witnessScript))
                        is OP_14 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 14, witnessScript))
                        is OP_15 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 15, witnessScript))
                        is OP_16 -> AddressFromPublicKeyScriptResult.Success(Bech32.encodeWitnessAddress(hrp, 16, witnessScript))
                        else -> AddressFromPublicKeyScriptResult.Failure.InvalidScript
                    }
                }

                else -> AddressFromPublicKeyScriptResult.Failure.InvalidScript
            }
        } catch (t: Throwable) {
            return AddressFromPublicKeyScriptResult.Failure.GenericError(t)
        }
    }

    @JvmStatic
    public fun addressFromPublicKeyScript(chainHash: ByteVector32, pubkeyScript: ByteArray): AddressFromPublicKeyScriptResult {
        return runCatching { Script.parse(pubkeyScript) }.fold(
            onSuccess = {
                addressFromPublicKeyScript(chainHash, it)
            },
            onFailure = {
                AddressFromPublicKeyScriptResult.Failure.InvalidScript
            }
        )
    }

    @JvmStatic
    public fun addressToPublicKeyScript(chainHash: ByteVector32, address: String): AddressToPublicKeyScriptResult {
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
                        AddressToPublicKeyScriptResult.Success(Script.pay2pkh(it.second))

                    it.first == Base58.Prefix.PubkeyAddress && chainHash == Block.LivenetGenesisBlock.hash ->
                        AddressToPublicKeyScriptResult.Success(Script.pay2pkh(it.second))

                    it.first == Base58.Prefix.ScriptAddressTestnet && (chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash || chainHash == Block.SignetGenesisBlock.hash) ->
                        AddressToPublicKeyScriptResult.Success(listOf(OP_HASH160, OP_PUSHDATA(it.second), OP_EQUAL))

                    it.first == Base58.Prefix.ScriptAddress && chainHash == Block.LivenetGenesisBlock.hash ->
                        AddressToPublicKeyScriptResult.Success(listOf(OP_HASH160, OP_PUSHDATA(it.second), OP_EQUAL))

                    else -> AddressToPublicKeyScriptResult.Failure.ChainHashMismatch
                }
            },
            onFailure = { _ ->
                runCatching { Bech32.decodeWitnessAddress(address) }.fold(
                    onSuccess = {
                        val witnessVersion = witnessVersions[it.second]
                        when {
                            witnessVersion == null -> AddressToPublicKeyScriptResult.Failure.InvalidWitnessVersion(it.second.toInt())
                            it.third.size != 20 && it.third.size != 32 -> AddressToPublicKeyScriptResult.Failure.InvalidBech32Address
                            it.first == "bc" && chainHash == Block.LivenetGenesisBlock.hash -> AddressToPublicKeyScriptResult.Success(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "tb" && chainHash == Block.TestnetGenesisBlock.hash -> AddressToPublicKeyScriptResult.Success(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "tb" && chainHash == Block.SignetGenesisBlock.hash -> AddressToPublicKeyScriptResult.Success(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            it.first == "bcrt" && chainHash == Block.RegtestGenesisBlock.hash -> AddressToPublicKeyScriptResult.Success(listOf(witnessVersion, OP_PUSHDATA(it.third)))
                            else -> AddressToPublicKeyScriptResult.Failure.ChainHashMismatch
                        }
                    },
                    onFailure = {
                        AddressToPublicKeyScriptResult.Failure.InvalidAddress
                    }
                )
            }
        )
    }
}