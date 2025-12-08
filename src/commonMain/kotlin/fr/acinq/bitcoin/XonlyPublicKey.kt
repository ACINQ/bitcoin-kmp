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

import kotlin.jvm.JvmField

/**
 * x-only pubkey, used with Schnorr signatures (see https://github.com/bitcoin/bips/tree/master/bip-0340)
 * we only store the x coordinate of the pubkey, the y coordinate is always even
 */
public data class XonlyPublicKey(@JvmField val value: ByteVector32) {
    public constructor(pub: PublicKey) : this(pub.value.drop(1).toByteArray().byteVector32())

    val publicKey: PublicKey = PublicKey(byteArrayOf(2) + value.toByteArray())

    public fun tweak(tapTweak: Crypto.TaprootTweak): ByteVector32 {
        val toHash = when (tapTweak) {
            is Crypto.TaprootTweak.KeyPathTweak -> value.toByteArray()
            is Crypto.TaprootTweak.ScriptPathTweak -> value.toByteArray() + tapTweak.merkleRoot.toByteArray()
        }
        return Crypto.taggedHash(toHash, "TapTweak")
    }

    /**
     * Tweak this key with an optional merkle root.
     *
     * @param tapTweak taproot tweak
     * @return an (x-only pubkey, parity) pair
     */
    public fun outputKey(tapTweak: Crypto.TaprootTweak): Pair<XonlyPublicKey, Boolean> = this + PrivateKey(tweak(tapTweak)).publicKey()

    /** Tweak this key with the merkle root of the given script tree. */
    public fun outputKey(scriptTree: ScriptTree): Pair<XonlyPublicKey, Boolean> = outputKey(scriptTree.hash())

    /** Tweak this key with the merkle root provided. */
    public fun outputKey(merkleRoot: ByteVector32): Pair<XonlyPublicKey, Boolean> = outputKey(Crypto.TaprootTweak.ScriptPathTweak(merkleRoot))

    /**
     * @param chainHash chain hash (i.e. hash of the genesis block of the chain we're on)
     * @return the BIP86 address for this key (i.e. the p2tr address for this key with an explicit absence of scripts).
     */
    public fun p2trAddress(chainHash: BlockHash): String {
        val (outputKey, _) = outputKey(Crypto.TaprootTweak.KeyPathTweak)
        return Bech32.encodeWitnessAddress(Bech32.hrp(chainHash), 1, outputKey.value.toByteArray())
    }

    /**
     * add a public key to this x-only key
     * @param that public key
     * @return a (key, parity) pair where `key` is the x-only-pubkey for `this` + `that` and `parity` is true if `this` + `that` is odd
     */
    public operator fun plus(that: PublicKey): Pair<XonlyPublicKey, Boolean> {
        val pub = publicKey + that
        return Pair(XonlyPublicKey(pub), pub.isOdd())
    }
}
