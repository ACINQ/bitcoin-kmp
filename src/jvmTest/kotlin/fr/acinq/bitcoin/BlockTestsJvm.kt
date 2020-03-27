package fr.acinq.bitcoin

import com.google.common.io.ByteStreams
import kotlinx.serialization.InternalSerializationApi
import org.junit.Test
import kotlin.test.assertEquals

@ExperimentalUnsignedTypes
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
        for (tx in block.tx) {
            for (txin in tx.txIn) {
                if (!OutPoint.isCoinbase(txin.outPoint)) {
                    val script = Script.parse(txin.signatureScript)
                    assert(txin.signatureScript == Script.write(script).byteVector())
                }
            }
            for (txout in tx.txOut) {
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

    @Test
    fun `compute proof of work`() {
        assertEquals(
            UInt256(Hex.decode("0000000000000000000000000000000000000000000000000000000400040004")),
            BlockHeader.blockProof(473956288)
        )
        assertEquals(
            UInt256(Hex.decode("0000000000000000000000000000000000000000000000000000010fc306ae30")),
            BlockHeader.blockProof(469823783)
        )
        assertEquals(
            UInt256(Hex.decode("000000000000000000000000000000000000000000000000000003177fdc0ed1")),
            BlockHeader.blockProof(458411200)
        )
        assertEquals(
            UInt256(Hex.decode("0000000000000000000000000000000000000000000000000000000672b107dd")),
            BlockHeader.blockProof(472363968)
        )
    }

    @Test
    fun `check proof of work`() {
        val headers = sequenceOf(
            "01000000d46774a07109e9863938acd67fd7adf0b265293a38283f29a7e2551600000000256713d0e1b31f2518e7f93b41b9392da12dcd15fd9b871d2f694bfa6e4aaa308d06c34fc0ff3f1c7520e9f3",
            "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b",
            "000000201af2487466dc0437a1fc545740abd82c9d51b5a4bab9e5fea5082200000000000b209c935968affb31bd1288e66203a2b635b902a2352f7867b85201f6baaf09044d0758c0cc521bd1cf559f",
            "00000020620187836ab16deef958960bc1f8321fe2c32971a447ba7888bc050000000000c91a344b1a95579235f66776652529c60fd50099af021977f073388abb44862e8fbdda58c0b3271ca4e63787"
        ).map { BlockHeader.read(it) }

        headers.forEach { assert(BlockHeader.checkProofOfWork(it)) }
    }

    @Test
    fun `calculate next work required`() {
        val header = BlockHeader(
            version = 2,
            hashPreviousBlock = ByteVector32.Zeroes,
            hashMerkleRoot = ByteVector32.Zeroes,
            time = 0L,
            bits = 0L,
            nonce = 0L
        )

        assert(
            BlockHeader.calculateNextWorkRequired(
                header.copy(time = 1262152739, bits = 0x1d00ffff),
                1261130161
            ) == 0x1d00d86aL
        )
        assert(
            BlockHeader.calculateNextWorkRequired(
                header.copy(time = 1233061996, bits = 0x1d00ffff),
                1231006505
            ) == 0x1d00ffffL
        )
        assert(
            BlockHeader.calculateNextWorkRequired(
                header.copy(time = 1279297671, bits = 0x1c05a3f4),
                1279008237
            ) == 0x1c0168fdL
        )
    }
}