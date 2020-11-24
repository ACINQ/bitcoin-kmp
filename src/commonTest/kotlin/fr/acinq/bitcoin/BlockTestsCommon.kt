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

package fr.acinq.bitcoin

import fr.acinq.bitcoin.reference.TransactionTestsCommon
import fr.acinq.secp256k1.Hex
import org.kodein.memory.file.openReadableFile
import org.kodein.memory.file.resolve
import org.kodein.memory.use
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BlockTestsCommon {
    private val blockData = run {
        val file = TransactionTestsCommon.resourcesDir().resolve("block1.dat")
        file.openReadableFile().use {
            val len = it.available
            // workaround for a bug in kotlin memory file where dstOffset cannot be 0 but is still ignored...
            val buffer = ByteArray(len)
            for (i in buffer.indices) buffer[i] = it.readByte()
            buffer
        }
    }

    @Test
    fun `read blocks`() {
        val block = Block.read(blockData)
        assertTrue(Block.checkProofOfWork(block))

        assertEquals(MerkleTree.computeRoot(block.tx.map { it.hash }), block.header.hashMerkleRoot)

        // check that we can deserialize and re-serialize scripts
        for (tx in block.tx) {
            for (txin in tx.txIn) {
                if (!OutPoint.isCoinbase(txin.outPoint)) {
                    val script = Script.parse(txin.signatureScript)
                    assertEquals(txin.signatureScript, Script.write(script).byteVector())
                }
            }
            for (txout in tx.txOut) {
                val script = Script.parse(txout.publicKeyScript)
                assertEquals(txout.publicKeyScript, Script.write(script).byteVector())
            }
        }
    }

    @Test
    fun `serialize and deserialize blocks`() {
        val block = Block.read(blockData)
        val check = Block.write(block)
        assertEquals(check.byteVector(), blockData.byteVector())
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

        headers.forEach { assertTrue(BlockHeader.checkProofOfWork(it)) }
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

        assertEquals(BlockHeader.calculateNextWorkRequired(header.copy(time = 1262152739, bits = 0x1d00ffff), 1261130161), 0x1d00d86aL)
        assertEquals(BlockHeader.calculateNextWorkRequired(header.copy(time = 1233061996, bits = 0x1d00ffff), 1231006505), 0x1d00ffffL)
        assertEquals(BlockHeader.calculateNextWorkRequired(header.copy(time = 1279297671, bits = 0x1c05a3f4), 1279008237), 0x1c0168fdL)
    }
}