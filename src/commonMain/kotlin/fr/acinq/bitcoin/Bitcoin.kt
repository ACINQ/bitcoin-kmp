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

public fun fixSize(data: ByteArray, size: Int): ByteArray = when {
    data.size == size -> data
    data.size < size -> ByteArray(size - data.size) + data
    else -> {
        throw RuntimeException("overflow")
    }
}

public fun <T> List<T>.updated(i: Int, t: T): List<T> = when (i) {
    0 -> listOf(t) + this.drop(1)
    this.lastIndex -> this.dropLast(1) + t
    else -> this.take(i) + t + this.take(this.size - i - 1)
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
    public fun addressFromPublicKeyScript(chainHash: ByteVector32, pubkeyScript: List<ScriptElt>): String? {
        return try {
            when {
                Script.isPay2pkh(pubkeyScript) -> {
                    val prefix = when (chainHash) {
                        Block.LivenetGenesisBlock.hash -> Base58.Prefix.PubkeyAddress
                        Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash -> Base58.Prefix.PubkeyAddressTestnet
                        else -> error("invalid chain hash")
                    }
                    Base58Check.encode(prefix, (pubkeyScript[2] as OP_PUSHDATA).data)
                }
                Script.isPay2sh(pubkeyScript) -> {
                    val prefix = when (chainHash) {
                        Block.LivenetGenesisBlock.hash -> Base58.Prefix.ScriptAddress
                        Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash -> Base58.Prefix.ScriptAddressTestnet
                        else -> error("invalid chain hash")
                    }
                    Base58Check.encode(prefix, (pubkeyScript[1] as OP_PUSHDATA).data)
                }
                Script.isNativeWitnessScript(pubkeyScript) -> {
                    val hrp = Bech32.hrp(chainHash)
                    val witnessScript = (pubkeyScript[1] as OP_PUSHDATA).data.toByteArray()
                    when (pubkeyScript[0]) {
                        is OP_0 -> when {
                            Script.isPay2wpkh(pubkeyScript) || Script.isPay2wsh(pubkeyScript) -> Bech32.encodeWitnessAddress(hrp, 0, witnessScript)
                            else -> null
                        }
                        is OP_1 -> Bech32.encodeWitnessAddress(hrp, 1, witnessScript)
                        is OP_2 -> Bech32.encodeWitnessAddress(hrp, 2, witnessScript)
                        is OP_3 -> Bech32.encodeWitnessAddress(hrp, 3, witnessScript)
                        is OP_4 -> Bech32.encodeWitnessAddress(hrp, 4, witnessScript)
                        is OP_5 -> Bech32.encodeWitnessAddress(hrp, 5, witnessScript)
                        is OP_6 -> Bech32.encodeWitnessAddress(hrp, 6, witnessScript)
                        is OP_7 -> Bech32.encodeWitnessAddress(hrp, 7, witnessScript)
                        is OP_8 -> Bech32.encodeWitnessAddress(hrp, 8, witnessScript)
                        is OP_9 -> Bech32.encodeWitnessAddress(hrp, 9, witnessScript)
                        is OP_10 -> Bech32.encodeWitnessAddress(hrp, 10, witnessScript)
                        is OP_11 -> Bech32.encodeWitnessAddress(hrp, 11, witnessScript)
                        is OP_12 -> Bech32.encodeWitnessAddress(hrp, 12, witnessScript)
                        is OP_13 -> Bech32.encodeWitnessAddress(hrp, 13, witnessScript)
                        is OP_14 -> Bech32.encodeWitnessAddress(hrp, 14, witnessScript)
                        is OP_15 -> Bech32.encodeWitnessAddress(hrp, 15, witnessScript)
                        is OP_16 -> Bech32.encodeWitnessAddress(hrp, 16, witnessScript)
                        else -> null
                    }
                }
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    @JvmStatic
    public fun addressFromPublicKeyScript(chainHash: ByteVector32, pubkeyScript: ByteArray): String? {
        return try {
            addressFromPublicKeyScript(chainHash, Script.parse(pubkeyScript))
        } catch (e: Exception) {
            null
        }
    }
}