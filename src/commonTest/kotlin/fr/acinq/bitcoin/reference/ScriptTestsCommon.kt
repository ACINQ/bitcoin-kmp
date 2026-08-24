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
import kotlinx.serialization.json.*
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

class ScriptTestsCommon {

    @Test
    fun `reference client script test`() {
        // 	["Format is: [[wit..., amount]?, scriptSig, scriptPubKey, flags, expected_scripterror, ... comments]"]
        val tests = TestHelpers.readResourceAsJson("data/script_tests.json")
        var count = 0
        tests.jsonArray.filter { it.jsonArray.size >= 4 }.forEach {
            runTest(it.jsonArray)
            count += 1
        }
        assertEquals(1233, count)
    }


    @Test
    fun `extra script tests`() {
        // additional tests that are not part of bitcoin core's test suite
        // we use same JSON format so we can easily run these tests with bitcoin core
        val json = Json { ignoreUnknownKeys = true }
        val tests = json.parseToJsonElement(
            """
           [
            [ "check that TOALTSTACK does increments opcode count" ],
            ["10 10 TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK", "ADD 20 EQUAL", "P2SH,STRICTENC", "OK"],
            ["10 10 TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK TOALTSTACK FROMALTSTACK", "ADD 20 EQUAL", "P2SH,STRICTENC", "TOO_MANY_OPS"],
            [ "check that unexecuted opcode do increment opcode count" ],
            ["1 1 0 IF NOP VER ELSE 1 NOTIF VERIFY RETURN TOALTSTACK FROMALTSTACK 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP IFDUP DEPTH DROP DUP NIP OVER PICK ROLL ROT SWAP TUCK SIZE EQUAL EQUALVERIFY RESERVED1 RESERVED2 1ADD 1SUB NEGATE ABS NOT 0NOTEQUAL ADD SUB BOOLAND BOOLOR NUMEQUAL NUMEQUALVERIFY NUMNOTEQUAL LESSTHAN GREATERTHAN LESSTHANOREQUAL MIN MAX WITHIN RIPEMD160 SHA1 SHA256 HASH160 HASH256 CODESEPARATOR CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY NOP1 CHECKLOCKTIMEVERIFY CHECKSEQUENCEVERIFY NOP4 NOP5 NOP6 NOP7 NOP8 NOP9 NOP10 CHECKSIGADD VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER ENDIF ENDIF", "", "P2SH,STRICTENC", "OK"],
            ["1 1 0 IF NOP VER VER ELSE 1 NOTIF VERIFY RETURN TOALTSTACK FROMALTSTACK 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP IFDUP DEPTH DROP DUP NIP OVER PICK ROLL ROT SWAP TUCK SIZE EQUAL EQUALVERIFY RESERVED1 RESERVED2 1ADD 1SUB NEGATE ABS NOT 0NOTEQUAL ADD SUB BOOLAND BOOLOR NUMEQUAL NUMEQUALVERIFY NUMNOTEQUAL LESSTHAN GREATERTHAN LESSTHANOREQUAL MIN MAX WITHIN RIPEMD160 SHA1 SHA256 HASH160 HASH256 CODESEPARATOR CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY NOP1 CHECKLOCKTIMEVERIFY CHECKSEQUENCEVERIFY NOP4 NOP5 NOP6 NOP7 NOP8 NOP9 NOP10 CHECKSIGADD VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER VER ENDIF ENDIF", "", "P2SH,STRICTENC", "TOO_MANY_OPS"],
            [ "the scriptSig of a P2SH-wrapped witness program must be exactly a single push of the redeem script" ],
            [["51", 0.00000000], "0x22 0x00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260", "HASH160 0x14 0x72c44f957fc011d97e3406667dca5b1c930c4026 EQUAL", "P2SH,WITNESS", "OK", "P2SH(P2WSH), exact scriptSig"],
            [["51", 0.00000000], "0 0x22 0x00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260", "HASH160 0x14 0x72c44f957fc011d97e3406667dca5b1c930c4026 EQUAL", "P2SH,WITNESS", "WITNESS_MALLEATED_P2SH", "P2SH(P2WSH), scriptSig prefixed with OP_0"],
            [["51", 0.00000000], "0x4c 0x22 0x00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260", "HASH160 0x14 0x72c44f957fc011d97e3406667dca5b1c930c4026 EQUAL", "P2SH,WITNESS", "WITNESS_MALLEATED_P2SH", "P2SH(P2WSH), redeem script pushed with OP_PUSHDATA1"],
            [ "a P2SH redeem script is a witness program only if the witness program is pushed with a direct push, and the version byte is OP_0 or OP_1-OP_16" ],
            [["51", 0.00000000], "0x23 0x004c204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260", "HASH160 0x14 0xcdcd15769e99f325875a362b7708e3083e3e13dd EQUAL", "P2SH,WITNESS", "WITNESS_UNEXPECTED", "P2SH redeem script with a non-minimal push of the witness program"],
            [["51", 0.00000000], "0x22 0x4f204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260", "HASH160 0x14 0x13fa440633ed7801ce99e82807c91f886db25029 EQUAL", "P2SH,WITNESS", "WITNESS_UNEXPECTED", "P2SH redeem script with OP_1NEGATE as witness version"]
            ]                                  
       """.trimIndent()
        )
        tests.jsonArray.filter { it.jsonArray.size >= 4 }.forEach {
            runTest(it.jsonArray)
        }
    }

    companion object {
        private val mapFlagNames = mapOf(
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
                        head.startsWith("0x") -> {
                            parseInternal(tail, acc + Hex.decode(head))
                        }
                        head.startsWith("'") && head.endsWith("'") -> parseInternal(tail, acc + Script.write(listOf(OP_PUSHDATA(head.drop(1).dropLast(1).encodeToByteArray()))))
                        else -> {
                            throw IllegalArgumentException("cannot parse $head")
                        }
                    }
                }
            }

            try {
                val tokens = input.split(' ').filterNot { it.isEmpty() }.map { it.removePrefix("OP_") }.toList()
                return parseInternal(tokens)

            } catch (t: Throwable) {
                throw RuntimeException("cannot parse $input", t)
            }
        }

        private fun creditTx(scriptPubKey: ByteArray, amount: Satoshi) = Transaction(
            version = 1,
            txIn = listOf(TxIn(OutPoint(TxHash(ByteArray(32)), -1), listOf(OP_0, OP_0), 0xffffffff)),
            txOut = listOf(TxOut(amount, scriptPubKey)),
            lockTime = 0
        )

        private fun spendingTx(scriptSig: ByteArray, tx: Transaction) = Transaction(
            version = 1,
            txIn = listOf(TxIn(OutPoint(TxHash(Crypto.hash256(Transaction.write(tx))), 0), scriptSig, 0xffffffff)),
            txOut = listOf(TxOut(tx.txOut[0].amount, ByteArray(0))),
            lockTime = 0
        )

        // use 0 btc if no amount is specified
        private fun runTest(
            witnessText: List<String>,
            scriptSigText: String,
            scriptPubKeyText: String,
            flags: String,
            comments: String?,
            expectedText: String
        ) = runTest(witnessText, 0L.toSatoshi(), scriptSigText, scriptPubKeyText, flags, comments, expectedText)

        private fun runTest(
            witnessText: List<String>,
            amount: Satoshi,
            scriptSigText: String,
            scriptPubKeyText: String,
            strFlags: String,
            comments: String?,
            expectedText: String
        ) {
            val witnessStack = mutableListOf<ByteVector>()
            val priv = PrivateKey(ByteVector32.One)
            var leaf: ScriptTree.Leaf? = null

            witnessText.map {
                when {
                    it.startsWith("#SCRIPT#") -> witnessStack.add(parseFromText(it.removePrefix("#SCRIPT#")).byteVector())
                    it.startsWith("#CONTROLBLOCK#") -> {
                        leaf = ScriptTree.Leaf(witnessStack.last(), Script.TAPROOT_LEAF_TAPSCRIPT)
                        val controlBlock = Script.ControlBlock.build(priv.xOnlyPublicKey(), leaf, leaf)
                        witnessStack.add(controlBlock)
                    }
                    else -> witnessStack.add(ByteVector(it))
                }
            }
            val witness = ScriptWitness(witnessStack)
            val scriptPubKey = if (scriptPubKeyText == "0x51 0x20 #TAPROOTOUTPUT#") {
                Script.write(Script.pay2tr(priv.xOnlyPublicKey(), leaf?.let { Crypto.TaprootTweak.ScriptPathTweak(it.hash()) } ?: Crypto.TaprootTweak.KeyPathTweak))
            } else {
                parseFromText(scriptPubKeyText)
            }
            val scriptSig = parseFromText(scriptSigText)
            val tx = spendingTx(scriptSig, creditTx(scriptPubKey, amount)).updateWitness(0, witness)
            var flags = parseScriptFlags(strFlags)
            if ((flags and SCRIPT_VERIFY_CLEANSTACK) != 0) {
                flags = flags or SCRIPT_VERIFY_P2SH
                flags = flags or SCRIPT_VERIFY_WITNESS
            }
            val expected = expectedText == "OK"

            fun doTest(flags: Int) {
                val ctx = Script.Context(tx, 0, amount, listOf())
                val runner = Script.Runner(ctx, flags)
                val result = try {
                    runner.verifyScripts(scriptSig, scriptPubKey, witness)
                } catch (t: Throwable) {
                    false
                }
                assertEquals(expected, result, "$comments with flags $flags")
            }

            doTest(flags)

            // Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
            repeat(256) {
                val extraFlags = Random.nextInt(ScriptFlags.MAX_SCRIPT_VERIFY_FLAGS)
                var combinedFlags = if (expected) flags and extraFlags.inv() else flags or extraFlags
                // Weed out some invalid flag combinations.
                if ((combinedFlags and SCRIPT_VERIFY_CLEANSTACK) != 0 && (combinedFlags.inv() and (SCRIPT_VERIFY_P2SH or SCRIPT_VERIFY_WITNESS) != 0)) return@repeat
                if ((combinedFlags and SCRIPT_VERIFY_WITNESS) != 0 && (combinedFlags.inv() and SCRIPT_VERIFY_P2SH != 0)) return@repeat
                doTest(combinedFlags)
            }
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