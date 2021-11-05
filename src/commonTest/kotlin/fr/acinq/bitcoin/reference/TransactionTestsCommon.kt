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
import kotlin.test.assertEquals
import kotlin.test.fail

class TransactionTestsCommon {
    companion object {
        fun resourcesDir() =
            Environment.findVariable("TEST_RESOURCES_PATH")?.let { Path(it) }
                ?: FileSystem.workingDir().resolve("src/commonTest/resources")

        fun readData(filename: String): JsonElement {
            val file = resourcesDir().resolve(filename)
            val raw = file.openReadableFile().use { it.readString() }
            val format = Json { ignoreUnknownKeys = true }
            return format.parseToJsonElement(raw)
        }

        fun process(tests: JsonArray, valid: Boolean): Int {
            var count = 0
            var comment = ""
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

        fun processSingle(testCase: JsonArray, valid: Boolean, comment: String? = null) {
            val prevoutMap = mutableMapOf<OutPoint, ByteVector>()
            val prevamountMap = mutableMapOf<OutPoint, Satoshi>()

            when {
                testCase[0].jsonArray.isNotEmpty() && testCase[1].jsonPrimitive.isString && testCase[2].jsonPrimitive.isString -> {
                    val serializedTransaction = testCase[1].jsonPrimitive.content
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
                                prevoutMap[OutPoint(ByteVector32(hash).reversed(), index)] = prevoutScript.byteVector()
                                val amount = it.jsonArray[3].jsonPrimitive.long.toSatoshi()
                                prevamountMap.put(OutPoint(ByteVector32(hash).reversed(), index), amount)
                            }
                            else -> {
                                fail("unexpected test data $testCase $comment")
                            }
                        }
                    }
                    val tx = Transaction.read(serializedTransaction, Protocol.PROTOCOL_VERSION)
                    val result = try {
                        val isTxValid = kotlin.runCatching { Transaction.validate(tx) }.isSuccess
                        if(testCase[2].jsonPrimitive.content == "BADTX") require(!isTxValid){ "$tx should be invalid"}
                        if(testCase[2].jsonPrimitive.content != "BADTX") require(isTxValid){ "$tx should be valid"}
                        val verifyFlags = ScriptTestsCommon.parseScriptFlags(testCase[2].jsonPrimitive.content)

                        for (i in 0..tx.txIn.lastIndex) {
                            if (tx.txIn[i].outPoint.isCoinbase) continue
                            val prevOutputScript = prevoutMap.getValue(tx.txIn[i].outPoint)
                            val amount = prevamountMap[tx.txIn[i].outPoint] ?: 0L.toSatoshi()
                            val ctx = Script.Context(tx, i, amount, listOf())
                            val runner = Script.Runner(ctx, if (valid) verifyFlags.inv() else verifyFlags)
                            if (!runner.verifyScripts(tx.txIn[i].signatureScript, prevOutputScript, tx.txIn[i].witness)) {
                                throw RuntimeException("tx ${tx.txid} does not spend its input #$i")
                            }
                        }
                        true
                    } catch (t: Throwable) {
                        false
                    }
                    assertEquals(valid, result, "failed valid=$valid test $testCase")
                }
                else -> {
                    fail("could not process test $testCase")
                }
            }
        }
    }

    @Test
    fun `reference valid tx tests`() {
        val tests = readData("data/tx_valid.json")
        val count = process(tests.jsonArray, true)
        assertEquals(119, count)
    }

    @Test
    fun `reference invalid tx tests`() {
        val tests = readData("data/tx_invalid.json")
        val count = process(tests.jsonArray, false)
        assertEquals(93, count)
    }
}
