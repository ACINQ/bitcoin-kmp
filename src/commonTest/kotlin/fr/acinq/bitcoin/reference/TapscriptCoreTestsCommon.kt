package fr.acinq.bitcoin.reference

import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.*
import org.kodein.memory.file.*
import org.kodein.memory.text.readString
import org.kodein.memory.use
import kotlin.test.*

class TapscriptCoreTestsCommon {
    @Test
    fun `tapscript tests`() {
        var count = 0
        TransactionTestsCommon.resourcesDir().resolve("data").resolve("taproot-functional-tests").listDir().forEach { dir ->
            dir.listDir().forEach {
                val json = readJson(it)
                run(json, it.name)
                count++
            }
        }
        assertEquals(count, 2760)
    }

    private fun readJson(path: Path): JsonObject {
        val format = Json { ignoreUnknownKeys = true }
        var raw = path.openReadableFile().use { it.readString() }.filterNot { c -> c == '\n' }
        if (raw.last() == ',') {
            raw = raw.dropLast(1)
        }

        return format.parseToJsonElement(raw).jsonObject
    }

    @Test
    fun `single test`() {
        val file = TransactionTestsCommon.resourcesDir().resolve("data").resolve("taproot-functional-tests").resolve("3").resolve("3c16caf4303dc387d0e90aa1266d0e4e1bf92ffc")
        val json = readJson(file)
        run(json, file.name)
    }

    fun run(json: JsonObject, name: String) {
        val tx = Transaction.read(json["tx"]!!.jsonPrimitive.content)
        val prevouts = json["prevouts"]!!.jsonArray.map { TxOut.read(it.jsonPrimitive.content) }
        val testCase = (json["success"] ?: json["failure"])!!.jsonObject
        val witness = testCase.jsonObject["witness"]!!.jsonArray.map { ByteVector.fromHex(it.jsonPrimitive.content) }
        val scriptSig = Hex.decode(testCase.jsonObject["scriptSig"]!!.jsonPrimitive.content)
        val i = json["index"]!!.jsonPrimitive.int
        val tx1 = tx
            .updateWitness(i, ScriptWitness(witness))
            .updateSigScript(i, scriptSig)
        val prevOutput = prevouts[i]
        val prevOutputScript = prevOutput.publicKeyScript
        val amount = prevOutput.amount
        val scriptFlags = ScriptTestsCommon.parseScriptFlags(json["flags"]!!.jsonPrimitive.content)
        val ctx = Script.Context(tx1, i, amount, prevouts)
        val runner = Script.Runner(ctx, scriptFlags, null)
        when (json["success"]) {
            null -> {
                val result = kotlin.runCatching {
                    runner.verifyScripts(tx1.txIn[i].signatureScript, prevOutputScript, tx1.txIn[i].witness)
                }.getOrDefault(false)
                assertFalse(result, "failure test $name failed")
            }
            else -> {
                val result = runner.verifyScripts(tx1.txIn[i].signatureScript, prevOutputScript, tx1.txIn[i].witness)
                assertTrue(result, "success test $name failed")
            }
        }
    }
}