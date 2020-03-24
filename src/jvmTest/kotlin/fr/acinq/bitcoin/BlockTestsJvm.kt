package fr.acinq.bitcoin

import com.google.common.io.ByteStreams
import kotlinx.serialization.InternalSerializationApi
import org.junit.Test

@ExperimentalStdlibApi
@InternalSerializationApi
class BlockTestsJvm {
    @Test
    fun `read blocks`() {
        val stream = javaClass.getResourceAsStream("/block1.dat")
        val block = Block.read(stream)
        // assert(Block.checkProofOfWork(block))

        assert(MerkleTree.computeRoot(block.tx.map { it.hash }) == block.header.hashMerkleRoot)

        // check that we can deserialize and re-serialize scripts
        for(tx in block.tx) {
            for(txin in tx.txIn) {
                if (!OutPoint.isCoinbase(txin.outPoint)) {
                    val script = Script.parse(txin.signatureScript)
                    assert(txin.signatureScript == Script.write(script).byteVector())
                }
            }
            for(txout in tx.txOut) {
                val script = Script.parse(txout.publicKeyScript)
                assert(txout.publicKeyScript == Script.write(script).byteVector())
            }
        }
    }

    @Test
    fun `serialize and deserialize blocks`() {
        val stream = javaClass.getResourceAsStream("/block1.dat")
        val bytes = ByteStreams.toByteArray(stream)
        val block = Block.read(bytes)
        val check = Block.write(block)
        assert(check.byteVector() == bytes.byteVector())
    }
}