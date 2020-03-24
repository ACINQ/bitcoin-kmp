package fr.acinq.bitcoin.reference

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import fr.acinq.bitcoin.*
import kotlinx.serialization.InternalSerializationApi
import org.junit.Test

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
            val prevamountMap = mutableMapOf<OutPoint, Satoshi>()

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
                                prevoutMap.put(OutPoint(ByteVector32(hash).reversed(), index.toLong()), prevoutScript.byteVector())
                            }
                            4 -> {
                                val hash = it[0].textValue()
                                val index = it[1].longValue()
                                val scriptPubKey = it[2].textValue()
                                val prevoutScript = ScriptTestsJvm.parseFromText(scriptPubKey)
                                prevoutMap.put(OutPoint(ByteVector32(hash).reversed(), index), prevoutScript.byteVector())
                                val amount = it[3].longValue()
                                prevamountMap.put(OutPoint(ByteVector32(hash).reversed(), index), Satoshi(amount))
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
                            val amount = prevamountMap.get(tx.txIn[i].outPoint) ?: Satoshi(0)
                            val ctx = Script.Context(tx, i, amount)
                            val runner = Script.Runner(ctx, ScriptTestsJvm.parseScriptFlags(verifyFlags))
                            if (!runner.verifyScripts(tx.txIn[i].signatureScript, prevOutputScript, tx.txIn[i].witness)) throw RuntimeException("tx ${tx.txid} does not spend its input # $i")
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
        //val json = """[[["6eb316926b1c5d567cd6f5e6a84fec606fc53d7b474526d1fff3948020c93dfe",0,"0x21 0x036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8 CHECKSIG",156250000],["f825690aee1b3dc247da796cacb12687a5e802429fd291cfd63e010f02cf1508",0,"0x00 0x20 0x5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0",4900000000]], "01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000", "P2SH,WITNESS,CONST_SCRIPTCODE"]"""
        val json = """[[["60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1",0,"1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG"]], "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000", "P2SH"]"""
        processSingle(mapper.readValue(json), true)

        val stream = javaClass.getResourceAsStream("/data/tx_valid.json")
        val tests = mapper.readValue<List<List<JsonNode>>>(stream)
        val count = process(tests, true)
        println("passed $count reference tx_valid tests")
    }

    @Test
    fun `reference invalid tx tests`() {
//        val json = """[[["6ca7ec7b1847f6bdbd737176050e6a08d66ccd55bb94ad24f4018024107a5827",0,"0x41 0x043b640e983c9690a14c039a2037ecc3467b27a0dcd58f19d76c7bc118d09fec45adc5370a1c5bf8067ca9f5557a4cf885fdb0fe0dcc9c3a7137226106fbc779a5 CHECKSIG VERIFY 1"]], "010000000127587a10248001f424ad94bb55cd6cd6086a0e05767173bdbdf647187beca76c000000004948304502201b822ad10d6adc1a341ae8835be3f70a25201bbff31f59cbb9c5353a5f0eca18022100ea7b2f7074e9aa9cf70aa8d0ffee13e6b45dddabf1ab961bda378bcdb778fa4701ffffffff0100f2052a010000001976a914fc50c5907d86fed474ba5ce8b12a66e0a4c139d888ac00000000", "P2SH"]"""
//        processSingle(mapper.readValue(json), false)

        val stream = javaClass.getResourceAsStream("/data/tx_invalid.json")
        val tests = mapper.readValue<List<List<JsonNode>>>(stream)
        val count = process(tests, false)
        println("passed $count reference tx_invalid tests")
    }
}
