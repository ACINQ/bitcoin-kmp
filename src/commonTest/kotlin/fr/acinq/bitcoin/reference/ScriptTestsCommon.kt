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
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_CLEANSTACK
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_DERSIG
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_LOW_S
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_MINIMALDATA
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_MINIMALIF
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_NONE
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_NULLDUMMY
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_NULLFAIL
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_P2SH
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_SIGPUSHONLY
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_STRICTENC
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_TAPROOT
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_WITNESS
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class ScriptTestsCommon {

    @Test
    fun `reference client script test`() {
        // 	["Format is: [[wit..., amount]?, scriptSig, scriptPubKey, flags, expected_scripterror, ... comments]"]
        val tests = TransactionTestsCommon.readData("data/script_tests.json")
        var count = 0
        tests.jsonArray.filter { it.jsonArray.size >= 4 }.forEach {
            runTest(it.jsonArray)
            count += 1
        }
        assertEquals(1203, count)
    }

    companion object {
        val mapFlagNames = mapOf(
            "NONE" to SCRIPT_VERIFY_NONE,
            "P2SH" to SCRIPT_VERIFY_P2SH,
            "STRICTENC" to SCRIPT_VERIFY_STRICTENC,
            "DERSIG" to SCRIPT_VERIFY_DERSIG,
            "LOW_S" to SCRIPT_VERIFY_LOW_S,
            "SIGPUSHONLY" to SCRIPT_VERIFY_SIGPUSHONLY,
            "MINIMALDATA" to SCRIPT_VERIFY_MINIMALDATA,
            "NULLDUMMY" to SCRIPT_VERIFY_NULLDUMMY,
            "DISCOURAGE_UPGRADABLE_NOPS" to SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" to SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            "CLEANSTACK" to SCRIPT_VERIFY_CLEANSTACK,
            "MINIMALIF" to SCRIPT_VERIFY_MINIMALIF,
            "NULLFAIL" to SCRIPT_VERIFY_NULLFAIL,
            "CHECKLOCKTIMEVERIFY" to SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" to SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" to SCRIPT_VERIFY_WITNESS,
            "WITNESS_PUBKEYTYPE" to SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
            "CONST_SCRIPTCODE" to SCRIPT_VERIFY_CONST_SCRIPTCODE,
            "TAPROOT" to SCRIPT_VERIFY_TAPROOT
        )

        fun parseScriptFlags(strFlags: String): Int =
            if (strFlags.isEmpty()) 0 else strFlags.split(",").map { mapFlagNames.getValue(it) }.fold(0) { a, b -> a or b }

        fun parseFromText(input: String): ByteArray {
            fun parseInternal(tokens: List<String>, acc: ByteArray = ByteArray(0)): ByteArray {
                return if (tokens.isEmpty()) acc else {
                    val head = tokens.first()
                    val tail = tokens.drop(1)
                    when {
                        head.matches(Regex("^-?[0-9]*$")) -> {
                            when {
                                head.toLong() == -1L -> parseInternal(tail, acc + OP_1NEGATE.code.toByte())
                                head.toLong() == 0L -> parseInternal(tail, acc + OP_0.code.toByte())
                                head.toLong() in 1..16 -> {
                                    val byte = (OP_1.code - 1 + head.toInt()).toByte()
                                    val bytes = arrayOf(byte).toByteArray()
                                    parseInternal(tail, acc + bytes)
                                }
                                else -> {
                                    val bytes = Script.encodeNumber(head.toLong())
                                    parseInternal(tail, acc + Script.write(listOf(OP_PUSHDATA(bytes))))
                                }
                            }
                        }
                        ScriptEltMapping.name2code.containsKey(head) -> parseInternal(tail, acc + ScriptEltMapping.name2code.getValue(head).toByte())
                        head.startsWith("0x") -> parseInternal(tail, acc + Hex.decode(head))
                        head.startsWith("'") && head.endsWith("'") -> parseInternal(tail, acc + Script.write(listOf(OP_PUSHDATA(head.drop(1).dropLast(1).encodeToByteArray()))))
                        else -> {
                            throw IllegalArgumentException("cannot parse $head")
                        }
                    }
                }
            }

            try {
                val tokens = input.split(' ').filterNot { it.isEmpty() }.map { it.removePrefix("OP_") }.toList()
                val bytes = parseInternal(tokens)
                return bytes

            } catch (t: Throwable) {
                throw RuntimeException("cannot parse $input", t)
            }
        }

        fun creditTx(scriptPubKey: ByteArray, amount: Satoshi) = Transaction(
            version = 1,
            txIn = listOf(TxIn(OutPoint(ByteArray(32), -1), listOf(OP_0, OP_0), 0xffffffff)),
            txOut = listOf(TxOut(amount, scriptPubKey)),
            lockTime = 0
        )

        fun spendingTx(scriptSig: ByteArray, tx: Transaction) = Transaction(
            version = 1,
            txIn = listOf(TxIn(OutPoint(Crypto.hash256(Transaction.write(tx)), 0), scriptSig, 0xffffffff)),
            txOut = listOf(TxOut(tx.txOut[0].amount, ByteArray(0))),
            lockTime = 0
        )

        // use 0 btc if no amount is specified
        fun runTest(
            witnessText: List<String>,
            scriptSigText: String,
            scriptPubKeyText: String,
            flags: String,
            comments: String?,
            expectedText: String
        ) = runTest(witnessText, 0L.toSatoshi(), scriptSigText, scriptPubKeyText, flags, comments, expectedText)

        fun runTest(
            witnessText: List<String>,
            amount: Satoshi,
            scriptSigText: String,
            scriptPubKeyText: String,
            flags: String,
            comments: String?,
            expectedText: String
        ) {
            val witness = ScriptWitness(witnessText.map { ByteVector(it) })
            val scriptPubKey = parseFromText(scriptPubKeyText)
            val scriptSig = parseFromText(scriptSigText)
            val tx = spendingTx(scriptSig, creditTx(scriptPubKey, amount)).updateWitness(0, witness)
            val ctx = Script.Context(tx, 0, amount, listOf())
            val runner = Script.Runner(ctx, parseScriptFlags(flags))

            val expected = expectedText == "OK"
            val result = try {
                runner.verifyScripts(scriptSig, scriptPubKey, witness)
            } catch (t: Throwable) {
                false
            }
            assertEquals(result, expected, comments)
        }

        fun runTest(testCase: JsonArray) {
            when {
                testCase.size == 4 && testCase[0].jsonPrimitive.isString -> {
                    val scriptSig = testCase[0].jsonPrimitive.content
                    val scriptPubKey = testCase[1].jsonPrimitive.content
                    val flags = testCase[2].jsonPrimitive.content
                    val expected = testCase[3].jsonPrimitive.content
                    runTest(listOf(), scriptSig, scriptPubKey, flags, null, expected)
                }
                testCase.size == 5 && testCase[0] is JsonArray -> {
                    val elements = testCase[0].jsonArray.toList()
                    val strings = elements.dropLast(1).map { it.jsonPrimitive.content }
                    val amount = (elements.last().jsonPrimitive.double * 100_000_000).toLong().toSatoshi()
                    val scriptSig = testCase[1].jsonPrimitive.content
                    val scriptPubKey = testCase[2].jsonPrimitive.content
                    val flags = testCase[3].jsonPrimitive.content
                    val expected = testCase[4].jsonPrimitive.content
                    val comments = null
                    runTest(strings, amount, scriptSig, scriptPubKey, flags, comments, expected)
                }
                testCase.size == 5 && testCase[0].jsonPrimitive.isString -> {
                    val scriptSig = testCase[0].jsonPrimitive.content
                    val scriptPubKey = testCase[1].jsonPrimitive.content
                    val flags = testCase[2].jsonPrimitive.content
                    val expected = testCase[3].jsonPrimitive.content
                    val comments = testCase[4].jsonPrimitive.content
                    runTest(listOf(), scriptSig, scriptPubKey, flags, comments, expected)
                }
                testCase.size == 6 && testCase[0] is JsonArray -> {
                    val elements = testCase[0].jsonArray.toList()
                    val strings = elements.dropLast(1).map { it.jsonPrimitive.content }
                    val amount = (elements.last().jsonPrimitive.double * 100_000_000).toLong().toSatoshi()
                    val scriptSig = testCase[1].jsonPrimitive.content
                    val scriptPubKey = testCase[2].jsonPrimitive.content
                    val flags = testCase[3].jsonPrimitive.content
                    val expected = testCase[4].jsonPrimitive.content
                    val comments = testCase[5].jsonPrimitive.content
                    runTest(strings, amount, scriptSig, scriptPubKey, flags, comments, expected)
                }
                else -> {
                    println("don't understand $testCase")
                }
            }
        }
    }
}