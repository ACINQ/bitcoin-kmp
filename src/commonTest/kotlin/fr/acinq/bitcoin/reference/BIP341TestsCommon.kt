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
import kotlin.test.assertNotNull

class BIP341TestsCommon {
    @Test
    fun `BIP341 reference tests -- key path spending`() {
        val tests = TestHelpers.readResourceAsJson("data/bip341_wallet_vectors.json").jsonObject["keyPathSpending"]!!
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

            val previousOutputs = (fullySignedTx.txIn.map { it.outPoint }).zip(utxosSpent).toMap()
            Transaction.correctlySpends(fullySignedTx, previousOutputs, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

            it.jsonObject["inputSpending"]!!.jsonArray.forEach {
                val given = it.jsonObject["given"]!!.jsonObject
                val hashType = given["hashType"]!!.jsonPrimitive.int
                val txinIndex = given["txinIndex"]!!.jsonPrimitive.int
                val internalPrivkey = PrivateKey.fromHex(given["internalPrivkey"]!!.jsonPrimitive.content)
                val merkleRoot = nullOrBytes(given["merkleRoot"]?.jsonPrimitive?.content)

                val internalPubkey = internalPrivkey.publicKey().xOnly()
                val intermediary = it.jsonObject["intermediary"]!!.jsonObject
                assertEquals(ByteVector32(intermediary["internalPubkey"]!!.jsonPrimitive.content), internalPubkey.value)
                val tweak = internalPubkey.tweak(Crypto.TaprootTweak.from(merkleRoot))
                assertEquals(ByteVector32(intermediary["tweak"]!!.jsonPrimitive.content), tweak)

                val tweakedPrivateKey = internalPrivkey.tweak(tweak)
                assertEquals(ByteVector32(intermediary["tweakedPrivkey"]!!.jsonPrimitive.content), tweakedPrivateKey.value)

                val hash = Transaction.hashForSigningTaprootKeyPath(rawUnsignedTx, txinIndex, utxosSpent, hashType)
                assertEquals(ByteVector32(intermediary["sigHash"]!!.jsonPrimitive.content), hash)

                val sig = Crypto.signSchnorr(hash, internalPrivkey, Crypto.TaprootTweak.from(merkleRoot))
                val witness = Script.witnessKeyPathPay2tr(sig, hashType)
                val expected = it.jsonObject["expected"]!!.jsonObject
                val witnessStack = expected["witness"]!!.jsonArray.map { jsonElt -> ByteVector(jsonElt.jsonPrimitive.content) }
                assertEquals(1, witnessStack.size)
                assertEquals(witnessStack.first(), witness.stack.first())
            }
        }
    }

    @Test
    fun `BIP341 reference tests -- script path spending`() {
        val tests = TestHelpers.readResourceAsJson("data/bip341_wallet_vectors.json").jsonObject["scriptPubKey"]!!
        tests.jsonArray.forEach { it ->
            val given = it.jsonObject["given"]!!.jsonObject
            val internalPubkey = XonlyPublicKey(ByteVector32.fromValidHex(given["internalPubkey"]!!.jsonPrimitive.content))
            val scriptTree = when (val json = it.jsonObject["given"]!!.jsonObject["scriptTree"]) {
                null, JsonNull -> null
                else -> scriptTreeFromJson(json)
            }

            val intermediary = it.jsonObject["intermediary"]!!.jsonObject
            val (tweakedKey, _) = internalPubkey.outputKey(Crypto.TaprootTweak.from(scriptTree?.hash()))
            scriptTree?.let { assertEquals(ByteVector32(intermediary["merkleRoot"]!!.jsonPrimitive.content), it.hash()) }
            assertEquals(ByteVector32(intermediary["tweakedPubkey"]!!.jsonPrimitive.content), tweakedKey.value)

            val expected = it.jsonObject["expected"]!!.jsonObject
            val script = Script.pay2tr(internalPubkey, scriptTree)
            assertEquals(ByteVector(expected["scriptPubKey"]!!.jsonPrimitive.content), Script.write(script).byteVector())
            val bip350Address = Bech32.encodeWitnessAddress("bc", 1.toByte(), tweakedKey.value.toByteArray())
            assertEquals(expected["bip350Address"]!!.jsonPrimitive.content, bip350Address)

            when (expected["scriptPathControlBlocks"]) {
                null, JsonNull -> Unit
                else -> {
                    // When control blocks are provided, recompute them for each script tree leaf and check that they match.
                    assertNotNull(scriptTree)
                    val controlBlocks = expected["scriptPathControlBlocks"]!!.jsonArray.map { ByteVector.fromHex(it.jsonPrimitive.content) }

                    fun loop(tree: ScriptTree, acc: ArrayList<ScriptTree.Leaf>) {
                        when (tree) {
                            is ScriptTree.Leaf -> acc.add(tree)
                            is ScriptTree.Branch -> {
                                loop(tree.left, acc)
                                loop(tree.right, acc)
                            }
                        }
                    }
                    // traverse the tree from left to right and top to bottom, this is the order that is used in the reference tests
                    val leaves = ArrayList<ScriptTree.Leaf>()
                    loop(scriptTree, leaves)
                    controlBlocks.forEachIndexed { index, expectedControlBlock ->
                        val scriptLeaf = leaves[index]
                        assertNotNull(scriptLeaf)
                        val computedControlBlock = Script.ControlBlock.build(internalPubkey, scriptTree, scriptLeaf)
                        assertEquals(expectedControlBlock, computedControlBlock)
                    }
                }
            }
        }
    }

    companion object {
        private fun nullOrBytes(input: String?): ByteVector32? = when (input) {
            null, "null" -> null
            else -> ByteVector32(input)
        }

        private fun scriptLeafFromJson(json: JsonElement): Pair<Int, ScriptTree.Leaf> = json.jsonObject["id"]!!.jsonPrimitive.int to ScriptTree.Leaf(
            script = ByteVector.fromHex(json.jsonObject["script"]!!.jsonPrimitive.content),
            leafVersion = json.jsonObject["leafVersion"]!!.jsonPrimitive.int
        )

        fun scriptTreeFromJson(json: JsonElement): ScriptTree = when (json) {
            is JsonObject -> scriptLeafFromJson(json).second
            is JsonArray -> {
                require(json.size == 2) { "script tree must contain exactly two branches: $json" }
                ScriptTree.Branch(scriptTreeFromJson(json[0]), scriptTreeFromJson(json[1]))
            }
            else -> error("unexpected $json")
        }
    }
}
