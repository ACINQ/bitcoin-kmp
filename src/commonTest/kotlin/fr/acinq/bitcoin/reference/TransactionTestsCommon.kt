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
import kotlinx.serialization.json.*
import org.kodein.memory.file.FileSystem
import org.kodein.memory.file.Path
import org.kodein.memory.file.openReadableFile
import org.kodein.memory.file.resolve
import org.kodein.memory.system.Environment
import org.kodein.memory.text.readString
import org.kodein.memory.use
import kotlin.test.Test

class TransactionTestsCommon {
    companion object {
        fun resourcesDir() =
            Environment.findVariable("TEST_RESOURCES_PATH")?.let { Path(it) }
                ?: FileSystem.currentDirectory.resolve("src/commonTest/resources")

        fun readData(filename: String): JsonElement {
            val file = resourcesDir().resolve(filename)
            val raw = file.openReadableFile().use { it.readString() }
            val format = Json { ignoreUnknownKeys = true }
            return format.parseToJsonElement(raw)
        }

        fun process(tests: JsonArray, valid: Boolean): Int {
            var count = 0
            var comment: String = ""
            tests.map {
                when (it.jsonArray.size) {
                    1 -> comment = it.jsonArray[0].jsonPrimitive.content
                    3 -> {
                        processSingle(it.jsonArray, valid, comment)
                        count += 1
                    }
                }
            }
            return count
        }

        fun processSingle(testCase: JsonArray, valid: Boolean, comment: String? = null): Unit {
            val prevoutMap = mutableMapOf<OutPoint, ByteVector>()
            val prevamountMap = mutableMapOf<OutPoint, Satoshi>()

            when {
                testCase[0].jsonArray.isNotEmpty() && testCase[1].jsonPrimitive.isString && testCase[2].jsonPrimitive.isString -> {
                    val serializedTransaction = testCase[1].jsonPrimitive.content
                    val verifyFlags = testCase[2].jsonPrimitive.content
                    val array = testCase[0].jsonArray
                    array.map {
                        when (it.jsonArray.size) {
                            3 -> {
                                val hash = it.jsonArray[0].jsonPrimitive.content
                                val index = it.jsonArray[1].jsonPrimitive.int
                                val scriptPubKey = it.jsonArray[2].jsonPrimitive.content
                                val prevoutScript = ScriptTestsCommon.parseFromText(scriptPubKey)
                                prevoutMap.put(
                                    OutPoint(ByteVector32(hash).reversed(), index.toLong()),
                                    prevoutScript.byteVector()
                                )
                            }
                            4 -> {
                                val hash = it.jsonArray[0].jsonPrimitive.content
                                val index = it.jsonArray[1].jsonPrimitive.long
                                val scriptPubKey = it.jsonArray[2].jsonPrimitive.content
                                val prevoutScript = ScriptTestsCommon.parseFromText(scriptPubKey)
                                prevoutMap.put(
                                    OutPoint(ByteVector32(hash).reversed(), index),
                                    prevoutScript.byteVector()
                                )
                                val amount = it.jsonArray[3].jsonPrimitive.long.toSatoshi()
                                prevamountMap.put(OutPoint(ByteVector32(hash).reversed(), index), amount)
                            }
                            else -> {
                                println("unexpected test data $testCase $comment")
                            }
                        }
                    }
                    val tx = Transaction.read(serializedTransaction, Protocol.PROTOCOL_VERSION)
                    val result = try {
                        Transaction.validate(tx)
                        for (i in 0..tx.txIn.lastIndex) {
                            if (tx.txIn[i].outPoint.isCoinbase) continue
                            val prevOutputScript = prevoutMap.getValue(tx.txIn[i].outPoint)
                            val amount = prevamountMap.get(tx.txIn[i].outPoint) ?: 0L.toSatoshi()
                            val ctx = Script.Context(tx, i, amount)
                            val runner = Script.Runner(ctx, ScriptTestsCommon.parseScriptFlags(verifyFlags))
                            if (!runner.verifyScripts(
                                    tx.txIn[i].signatureScript,
                                    prevOutputScript,
                                    tx.txIn[i].witness
                                )
                            ) throw RuntimeException("tx ${tx.txid} does not spend its input # $i")
                        }
                        true
                    } catch (t: Throwable) {
                        false
                    }
                    if (result != valid) {
                        println("failed valid=$valid test $testCase!!")
                    }
                }
                else -> {

                }
            }
        }
    }

    @Test
    fun `reference valid tx tests`() {
        val json = """[[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1",0,"1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]], "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "P2SH"]"""
        processSingle(Json { ignoreUnknownKeys = true }.parseToJsonElement(json).jsonArray, true)

        val tests = readData("data/tx_valid.json")
        val count = process(tests.jsonArray, true)
        println("passed $count reference tx_valid tests")
    }

    @Test
    fun `reference invalid tx tests`() {
        val tests = readData("data/tx_invalid.json")
        val count = process(tests.jsonArray, false)
        println("passed $count reference tx_invalid tests")
    }
}
