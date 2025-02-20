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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

class TransactionTestsCommon {
    companion object {
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

        private fun processSingle(testCase: JsonArray, valid: Boolean, comment: String? = null) {
            val prevoutMap = mutableMapOf<OutPoint, ByteVector>()
            val prevamountMap = mutableMapOf<OutPoint, Satoshi>()

            when {
                testCase[0].jsonArray.isNotEmpty() && testCase[1].jsonPrimitive.isString && testCase[2].jsonPrimitive.isString -> {
                    val serializedTransaction = testCase[1].jsonPrimitive.content
                    val array = testCase[0].jsonArray
                    array.map {
                        when (it.jsonArray.size) {
                            3 -> {
                                val txid = it.jsonArray[0].jsonPrimitive.content
                                val index = it.jsonArray[1].jsonPrimitive.int
                                val scriptPubKey = it.jsonArray[2].jsonPrimitive.content
                                val prevoutScript = ScriptTestsCommon.parseFromText(scriptPubKey)
                                prevoutMap.put(
                                    OutPoint(TxId(txid), index.toLong()),
                                    prevoutScript.byteVector()
                                )
                            }
                            4 -> {
                                val txid = it.jsonArray[0].jsonPrimitive.content
                                val index = it.jsonArray[1].jsonPrimitive.long
                                val scriptPubKey = it.jsonArray[2].jsonPrimitive.content
                                val prevoutScript = ScriptTestsCommon.parseFromText(scriptPubKey)
                                prevoutMap[OutPoint(TxId(txid), index)] = prevoutScript.byteVector()
                                val amount = it.jsonArray[3].jsonPrimitive.long.toSatoshi()
                                prevamountMap.put(OutPoint(TxId(txid), index), amount)
                            }
                            else -> {
                                fail("unexpected test data $testCase $comment")
                            }
                        }
                    }
                    val tx = Transaction.read(serializedTransaction, Protocol.PROTOCOL_VERSION)
                    val result = try {
                        val isTxValid = kotlin.runCatching { Transaction.validate(tx) }.isSuccess
                        if (testCase[2].jsonPrimitive.content == "BADTX") require(!isTxValid) { "$tx should be invalid" }
                        if (testCase[2].jsonPrimitive.content != "BADTX") require(isTxValid) { "$tx should be valid" }
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
        val tests = TestHelpers.readResourceAsJson("data/tx_valid.json")
        val count = process(tests.jsonArray, true)
        assertEquals(119, count)
    }

    @Test
    fun `reference invalid tx tests`() {
        val tests = TestHelpers.readResourceAsJson("data/tx_invalid.json")
        val count = process(tests.jsonArray, false)
        assertEquals(93, count)
    }

    @Test
    fun `input and output weights`() {
        val publicKey1 = PublicKey.fromHex("03949633a194a43a310c5a593aada2f2d4a4e3c181880e2b396facfb2130a7f0b5")
        val publicKey2 = PublicKey.fromHex("02cf5642ac302c004f429b1d9334ac3f93f65ae4df2fb6bf23af3a848166afc662")
        val sig = ByteVector("f55bcf4c0650024f421bef9f47f9967fe3015b8ceeda8328185d0f2e73e8c30980e95282b1a73c8d30ceae3c40a9d6df952fd93ea027f6d2a41f6b21dcb1afbef37e81988e8f770cca")
        val txId = TxId("2f8dbf25b36aef3ab1c14c302e3d07fddd8a9d860126bc6a03e8533bb6a31cbe")

        val p2wpkhInputNoWitness = TxIn(OutPoint(txId, 3), ByteVector.empty, 0)
        val p2wpkhInputWithWitness = TxIn(OutPoint(txId, 3), ByteVector.empty, 0, Script.witnessPay2wpkh(publicKey1, sig))
        // See https://bitcoin.stackexchange.com/questions/100159/what-is-the-size-and-weight-of-a-p2wpkh-input
        assertEquals(p2wpkhInputNoWitness.weight(), 164)
        assertEquals(p2wpkhInputWithWitness.weight(), 273)

        // This is similar to a lightning channel funding input.
        val p2wshInputWithWitness = TxIn(OutPoint(txId, 3), ByteVector.empty, 0, Script.witnessMultiSigMofN(listOf(publicKey1, publicKey2), listOf(sig, sig)))
        assertEquals(p2wshInputWithWitness.weight(), 386)

        val p2wpkhOutput = TxOut(Satoshi(150_000), Script.pay2wpkh(publicKey1))
        val p2wshOutput = TxOut(Satoshi(150_000), Script.pay2wsh(Script.createMultiSigMofN(1, listOf(publicKey1, publicKey2))))
        val p2trOutput = TxOut(Satoshi(150_000), Script.pay2tr(publicKey1.xOnly()))
        // See https://bitcoin.stackexchange.com/questions/66428/what-is-the-size-of-different-bitcoin-transaction-types
        assertEquals(p2wpkhOutput.weight(), 124)
        assertEquals(p2wshOutput.weight(), 172)
        assertEquals(p2trOutput.weight(), 172)
    }
}
