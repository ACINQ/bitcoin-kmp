package fr.acinq.bitcoin.reference

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
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
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_WITNESS
import fr.acinq.bitcoin.ScriptFlags.SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
import fr.acinq.bitcoin.crypto.Crypto
import kotlinx.serialization.InternalSerializationApi
import org.junit.Test

@InternalSerializationApi
@ExperimentalStdlibApi
class ScriptTestsJvm {
    val mapper = jacksonObjectMapper()

    @Test
    fun `error #1`() {
        val raw = """["0x48 0x304502202de8c03fc525285c9c535631019a5f2af7c6454fa9eb392a3756a4917c420edd02210046130bf2baf7cfc065067c8b9e33a066d9c15edcea9feb0ca2d233e3597925b401", "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG", "", "OK", "P2PK with too much S padding but no DERSIG"]"""
        runTest(mapper.readValue(raw))
    }

    @Test
    fun `reference client script test`() {
        val stream = javaClass.getResourceAsStream("/data/script_tests.json")
        // 	["Format is: [[wit..., amount]?, scriptSig, scriptPubKey, flags, expected_scripterror, ... comments]"]
        val tests = mapper.readValue<List<List<JsonNode>>>(stream)
        var count = 0
        tests.filter { it -> it.size >= 4 }.forEach { it ->
            runTest(it)
            count += 1
        }
        println("passed $count reference tests")
    }


    @ExperimentalStdlibApi
    @InternalSerializationApi
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
                "CONST_SCRIPTCODE" to SCRIPT_VERIFY_CONST_SCRIPTCODE
        )

        fun parseScriptFlags(strFlags: String): Int = if (strFlags.isEmpty()) 0 else strFlags.split(",").map { it -> mapFlagNames.getValue(it) }.fold(0) { a, b -> a or b }

        fun parseFromText(input: String): ByteArray {
            fun parseInternal(tokens: List<String>, acc: ByteArray = ByteArray(0)): ByteArray {
                return if (tokens.isEmpty()) acc else {
                    val head = tokens.first()
                    val tail = tokens.drop(1)
                    when {
                        head.matches(Regex("^-?[0-9]*$")) -> {
                             when {
                                head.toLong() == -1L -> parseInternal(tail, acc + ScriptEltMapping.elt2code.getValue(OP_1NEGATE).toByte())
                                head.toLong() == 0L -> parseInternal(tail, acc + ScriptEltMapping.elt2code.getValue(OP_0).toByte())
                                head.toLong() in 1..16 -> {
                                    val byte = (ScriptEltMapping.elt2code.getValue(OP_1) - 1 + head.toInt()).toByte()
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
                        head.startsWith("'") && head.endsWith("'") -> parseInternal(tail, acc + Script.write(listOf(OP_PUSHDATA(head.drop(1).dropLast(1).toByteArray(charset("UTF-8"))))))
                        else -> {
                            throw IllegalArgumentException("cannot parse $head")
                        }
                    }
                }
            }

            try {
                val tokens = input.split(' ').filterNot { it -> it.isEmpty() }.map { it -> it.removePrefix("OP_") }.toList()
                val bytes = parseInternal(tokens)
                return bytes

            } catch (t: Throwable) {
                throw RuntimeException("cannot parse $input", t)
            }
        }

        fun creditTx(scriptPubKey: ByteArray, amount: Satoshi) = Transaction(version = 1,
                txIn = listOf(TxIn(OutPoint(ByteArray(32), -1), listOf(OP_0, OP_0), 0xffffffff)),
                txOut = listOf(TxOut(amount, scriptPubKey)),
                lockTime = 0)

        fun spendingTx(scriptSig: ByteArray, tx: Transaction) = Transaction(version = 1,
                txIn = listOf(TxIn(OutPoint(Crypto.hash256(Transaction.write(tx)), 0), scriptSig, 0xffffffff)),
                txOut = listOf(TxOut(tx.txOut[0].amount, ByteArray(0))),
                lockTime = 0)

        // use 0 btc if no amount is specified
        fun runTest(witnessText: List<String>, scriptSigText: String, scriptPubKeyText: String, flags: String, comments: String?, expectedText: String): Unit =
                runTest(witnessText, Satoshi(0), scriptSigText, scriptPubKeyText, flags, comments, expectedText)

        fun runTest(witnessText: List<String>, amount: Satoshi, scriptSigText: String, scriptPubKeyText: String, flags: String, comments: String?, expectedText: String): Unit {
            val witness = ScriptWitness(witnessText.map { it -> ByteVector(it) })
            val scriptPubKey = parseFromText(scriptPubKeyText)
            val scriptSig = parseFromText(scriptSigText)
            val tx = spendingTx(scriptSig, creditTx(scriptPubKey, amount)).updateWitness(0, witness)
            val ctx = Script.Context(tx, 0, amount)
            val runner = Script.Runner(ctx, parseScriptFlags(flags))

            val expected = expectedText == "OK"
            val result = try {
                runner.verifyScripts(scriptSig, scriptPubKey, witness)
            } catch (t: Throwable) {
                false
            }
            if (result != expected) {
                throw RuntimeException(comments ?: "")
            }
        }

        fun runTest(it: List<JsonNode>) {
            when {
                it.size == 4 && it[0].isTextual -> {
                    val scriptSig = it[0].textValue()
                    val scriptPubKey = it[1].textValue()
                    val flags = it[2].textValue()
                    val expected = it[3].textValue()
                    runTest(listOf(), scriptSig, scriptPubKey, flags, null, expected)
                }
                it.size == 5 && it[0].isTextual -> {
                    val scriptSig = it[0].textValue()
                    val scriptPubKey = it[1].textValue()
                    val flags = it[2].textValue()
                    val expected = it[3].textValue()
                    val comments = it[4].textValue()
                    runTest(listOf(), scriptSig, scriptPubKey, flags, comments, expected)
                }
                it.size == 5 && it[0].isArray -> {
                    val elements = it[0].elements().asSequence().toList()
                    val strings = elements.dropLast(1).map { it.textValue() }
                    val amount = Satoshi((elements.last().doubleValue() * 100_000_000).toLong())
                    val scriptSig = it[1].textValue()
                    val scriptPubKey = it[2].textValue()
                    val flags = it[3].textValue()
                    val expected = it[4].textValue()
                    val comments = null
                    runTest(strings, amount, scriptSig, scriptPubKey, flags, comments, expected)
                }
                it.size == 6 && it[0].isArray -> {
                    val elements = it[0].elements().asSequence().toList()
                    val strings = elements.dropLast(1).map { it.textValue() }
                    val amount = Satoshi((elements.last().doubleValue() * 100_000_000).toLong())
                    val scriptSig = it[1].textValue()
                    val scriptPubKey = it[2].textValue()
                    val flags = it[3].textValue()
                    val expected = it[4].textValue()
                    val comments = it[5].textValue()
                    runTest(strings, amount, scriptSig, scriptPubKey, flags, comments, expected)
                }
                else -> {
                    println("don't understand $it")
                }
            }
        }
    }
}