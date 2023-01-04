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
package fr.acinq.bitcoin.reference

import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals

class BIP341TestsCommon {
    @Test
    fun `BIP341 reference tests -- key path spending`() {
        val tests = TransactionTestsCommon.readData("data/bip341_wallet_vectors.json").jsonObject["keyPathSpending"]!!
        tests.jsonArray.forEach { it ->
            val fullySignedTx = Transaction.read(it.jsonObject["auxiliary"]!!.jsonObject["fullySignedTx"]!!.jsonPrimitive.content)
            val rawUnsignedTx = Transaction.read(it.jsonObject["given"]!!.jsonObject["rawUnsignedTx"]!!.jsonPrimitive.content)
            val utxosSpent = it.jsonObject["given"]!!.jsonObject["utxosSpent"]!!.jsonArray.map {
                TxOut(it.jsonObject["amountSats"]!!.jsonPrimitive.long.sat(), Hex.decode(it.jsonObject["scriptPubKey"]!!.jsonPrimitive.content))
            }
            val hashAmounts = it.jsonObject["intermediary"]!!.jsonObject["hashAmounts"]!!.jsonPrimitive.content
            val hashOutputs = it.jsonObject["intermediary"]!!.jsonObject["hashOutputs"]!!.jsonPrimitive.content
            val hashPrevouts = it.jsonObject["intermediary"]!!.jsonObject["hashPrevouts"]!!.jsonPrimitive.content
            val hashScriptPubkeys = it.jsonObject["intermediary"]!!.jsonObject["hashScriptPubkeys"]!!.jsonPrimitive.content
            val hashSequences = it.jsonObject["intermediary"]!!.jsonObject["hashSequences"]!!.jsonPrimitive.content

            assertEquals(hashAmounts, Hex.encode(Transaction.amountsSha256(utxosSpent)))
            assertEquals(hashOutputs, Hex.encode(Transaction.outputsSha256(rawUnsignedTx)))
            assertEquals(hashPrevouts, Hex.encode(Transaction.prevoutsSha256(rawUnsignedTx)))
            assertEquals(hashScriptPubkeys, Hex.encode(Transaction.scriptPubkeysSha256(utxosSpent)))
            assertEquals(hashSequences, Hex.encode(Transaction.sequencesSha256(rawUnsignedTx)))

            val previousOutputs = (fullySignedTx.txIn.map {it.outPoint}).zip(utxosSpent).toMap()
            Transaction.correctlySpends(fullySignedTx, previousOutputs, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

            it.jsonObject["inputSpending"]!!.jsonArray.forEach {
                val given = it.jsonObject["given"]!!.jsonObject
                val hashType = given["hashType"]!!.jsonPrimitive.int
                val txinIndex = given["txinIndex"]!!.jsonPrimitive.int
                val internalPrivkey = PrivateKey.fromHex(given["internalPrivkey"]!!.jsonPrimitive.content)
                val merkleRoot = nullOrBytes(given["merkleRoot"]?.jsonPrimitive?.content)

                val internalPubkey = XonlyPublicKey(internalPrivkey.publicKey())
                val intermediary = it.jsonObject["intermediary"]!!.jsonObject
                assertEquals(ByteVector32(intermediary["internalPubkey"]!!.jsonPrimitive.content), internalPubkey.value)
                val tweak = internalPubkey.tweak(if (merkleRoot == null) Crypto.TaprootTweak.NoScriptTweak else Crypto.TaprootTweak.ScriptTweak(merkleRoot))
                assertEquals(ByteVector32(intermediary["tweak"]!!.jsonPrimitive.content), tweak)

                val tweakedPrivateKey = internalPrivkey.tweak(tweak)
                assertEquals(ByteVector32(intermediary["tweakedPrivkey"]!!.jsonPrimitive.content), tweakedPrivateKey.value)

                val hash = Transaction.hashForSigningSchnorr(rawUnsignedTx, txinIndex, utxosSpent, hashType, 0)
                assertEquals(ByteVector32(intermediary["sigHash"]!!.jsonPrimitive.content), hash)

                val sig = Crypto.signSchnorr(hash, internalPrivkey, if (merkleRoot == null) Crypto.TaprootTweak.NoScriptTweak else Crypto.TaprootTweak.ScriptTweak(merkleRoot))
                val witness = when (hashType) {
                    SigHash.SIGHASH_DEFAULT -> sig
                    else -> (sig + byteArrayOf(hashType.toByte()))
                }
                val expected = it.jsonObject["expected"]!!.jsonObject
                val witnessStack = expected["witness"]!!.jsonArray.map { jsonElt -> ByteVector(jsonElt.jsonPrimitive.content) }
                assertEquals(1, witnessStack.size)
                assertEquals(witnessStack.first(), witness)
            }
        }
    }

    @Test
    fun `BIP341 reference tests -- script path spending`() {
        val tests = TransactionTestsCommon.readData("data/bip341_wallet_vectors.json").jsonObject["scriptPubKey"]!!
        tests.jsonArray.forEach { it ->
            val given = it.jsonObject["given"]!!.jsonObject
            val internalPubkey = XonlyPublicKey(ByteVector32.fromValidHex(given["internalPubkey"]!!.jsonPrimitive.content))
            val scriptTree = when (val json = it.jsonObject["given"]!!.jsonObject["scriptTree"]) {
                null, JsonNull -> null
                else -> read(json) { fromJson(it) }
            }

            val intermediary = it.jsonObject["intermediary"]!!.jsonObject
            val merkleRoot = scriptTree?.let { ScriptTree.hash(it) }
            val (tweakedKey, parity) = internalPubkey.outputKey(if (merkleRoot == null) Crypto.TaprootTweak.NoScriptTweak else Crypto.TaprootTweak.ScriptTweak(merkleRoot))
            merkleRoot?.let { assertEquals(ByteVector32(intermediary["merkleRoot"]!!.jsonPrimitive.content), it) }
            assertEquals(ByteVector32(intermediary["tweakedPubkey"]!!.jsonPrimitive.content), tweakedKey.value)

            val expected = it.jsonObject["expected"]!!.jsonObject
            val script = Script.write(listOf(OP_1, OP_PUSHDATA(tweakedKey.value))).byteVector()
            assertEquals(ByteVector(expected["scriptPubKey"]!!.jsonPrimitive.content), script)
            val bip350Address = Bech32.encodeWitnessAddress("bc", 1.toByte(), tweakedKey.value.toByteArray())
            assertEquals(expected["bip350Address"]!!.jsonPrimitive.content, bip350Address)

            when (expected["scriptPathControlBlocks"]) {
                null, JsonNull -> Unit
                else -> {
                    // when control blocks are provided, recompute them for each script tree leaf and check that they match
                    val controlBlocks = expected["scriptPathControlBlocks"]!!.jsonArray.map { ByteVector.fromHex(it.jsonPrimitive.content) }
                    val paths = mutableListOf<Pair<Int, ByteArray>>()
                    merklePath(scriptTree!!) { leafVersion, hashes -> paths.add(Pair(leafVersion, hashes)) }
                    val computed = paths.map {
                        // for each leaf in the script tree the control block is:
                        // leaf version + parity (1 byte) || internal pub key (32 bytes) || merkle path for this leaf (N * 32 bytes)
                        (byteArrayOf((if (parity) it.first + 1 else it.first).toByte()) + internalPubkey.value.toByteArray() + it.second).byteVector()
                    }
                    assertEquals(controlBlocks, computed)
                }
            }
        }
    }

    private fun nullOrBytes(input: String?): ByteVector32? = when (input) {
        null, "null" -> null
        else -> ByteVector32(input)
    }

    companion object {
        fun fromJson(json: JsonElement): ScriptLeaf = ScriptLeaf(
            id = json.jsonObject["id"]!!.jsonPrimitive.int,
            script = ByteVector.fromHex(json.jsonObject["script"]!!.jsonPrimitive.content),
            leafVersion = json.jsonObject["leafVersion"]!!.jsonPrimitive.int
        )

        fun <T> read(json: JsonElement, f: (JsonElement) -> T): ScriptTree<T> = when (json) {
            is JsonObject -> ScriptTree.Leaf(f(json))
            is JsonArray -> ScriptTree.Branch(read(json[0], f), read(json[1], f))
            else -> error("unexpected $json")
        }

        /**
         * computes the merkle paths for each leaf in the merkle tree.
         *
         * the input tree is traversed down and each time we reach a leaf. `onLeaf` will be call with the leaf version and the merkle path for this leaf (i.e. the concatenated
         * list of hashes you have to provide to recompute the tree hash from this leaf)
         */
        fun merklePath(tree: ScriptTree<ScriptLeaf>, hashes: ByteArray = byteArrayOf(), onLeaf: (Int, ByteArray) -> Unit) {
            when (tree) {
                is ScriptTree.Leaf -> onLeaf(tree.value.leafVersion, hashes)
                is ScriptTree.Branch -> {
                    merklePath(tree.left, ScriptTree.hash(tree.right).toByteArray() + hashes, onLeaf)
                    merklePath(tree.right, ScriptTree.hash(tree.left).toByteArray() + hashes, onLeaf)
                }
            }
        }
    }
}
