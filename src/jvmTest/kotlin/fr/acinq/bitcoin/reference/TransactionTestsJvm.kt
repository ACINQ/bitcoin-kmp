package fr.acinq.bitcoin.reference

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import fr.acinq.bitcoin.*
import kotlinx.serialization.InternalSerializationApi
import org.junit.Test

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
@InternalSerializationApi
class TransactionTestsJvm {
    val mapper = jacksonObjectMapper()

    @InternalSerializationApi
    @ExperimentalStdlibApi
    companion object {
        fun process(tests: List<List<JsonNode>>, valid: Boolean): Int {
            var count = 0
            var comment: String = ""
            tests.map {
                when (it.size) {
                    1 -> comment = it[0].textValue()
                    3 -> {
                        processSingle(it, valid, comment)
                        count += 1
                    }
                }
            }
            return count
        }

        fun processSingle(it: List<JsonNode>, valid: Boolean, comment: String? = null): Unit {
            val prevoutMap = mutableMapOf<OutPoint, ByteVector>()
            val prevamountMap = mutableMapOf<OutPoint, Long>()

            when {
                it[0].isArray && it[1].isTextual && it[2].isTextual -> {
                    val serializedTransaction = it[1].textValue()
                    val verifyFlags = it[2].textValue()
                    val array = it[0]
                    array.map {
                        when (it.count()) {
                            3 -> {
                                val hash = it[0].textValue()
                                val index = it[1].intValue()
                                val scriptPubKey = it[2].textValue()
                                val prevoutScript = ScriptTestsJvm.parseFromText(scriptPubKey)
                                prevoutMap.put(
                                    OutPoint(ByteVector32(hash).reversed(), index.toLong()),
                                    prevoutScript.byteVector()
                                )
                            }
                            4 -> {
                                val hash = it[0].textValue()
                                val index = it[1].longValue()
                                val scriptPubKey = it[2].textValue()
                                val prevoutScript = ScriptTestsJvm.parseFromText(scriptPubKey)
                                prevoutMap.put(
                                    OutPoint(ByteVector32(hash).reversed(), index),
                                    prevoutScript.byteVector()
                                )
                                val amount = it[3].longValue()
                                prevamountMap.put(OutPoint(ByteVector32(hash).reversed(), index), amount)
                            }
                            else -> {
                                println("unexpected test data $it $comment")
                            }
                        }
                    }
                    val tx = Transaction.read(serializedTransaction, Protocol.PROTOCOL_VERSION)
                    val result = try {
                        Transaction.validate(tx)
                        for (i in 0..tx.txIn.lastIndex) {
                            if (tx.txIn[i].outPoint.isCoinbase) continue
                            val prevOutputScript = prevoutMap.getValue(tx.txIn[i].outPoint)
                            val amount = prevamountMap.get(tx.txIn[i].outPoint) ?: 0
                            val ctx = Script.Context(tx, i, amount)
                            val runner = Script.Runner(ctx, ScriptTestsJvm.parseScriptFlags(verifyFlags))
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
                        println("failed valid=$valid test $it!!")
                    }
                }
                else -> {

                }
            }
        }
    }

    @Test
    fun `reference valid tx tests`() {
        val json =
            """[[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1",0,"1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]], "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "P2SH"]"""
        processSingle(mapper.readValue(json), true)

        val stream = javaClass.getResourceAsStream("/data/tx_valid.json")
        val tests = mapper.readValue<List<List<JsonNode>>>(stream)
        val count = process(tests, true)
        println("passed $count reference tx_valid tests")
    }

    @Test
    fun `reference invalid tx tests`() {
        val stream = javaClass.getResourceAsStream("/data/tx_invalid.json")
        val tests = mapper.readValue<List<List<JsonNode>>>(stream)
        val count = process(tests, false)
        println("passed $count reference tx_invalid tests")
    }
}
