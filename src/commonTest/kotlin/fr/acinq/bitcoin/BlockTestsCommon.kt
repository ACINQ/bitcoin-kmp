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

import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.readNBytes
import fr.acinq.bitcoin.reference.TransactionTestsCommon
import fr.acinq.secp256k1.Hex
import org.kodein.memory.file.openReadableFile
import org.kodein.memory.file.resolve
import org.kodein.memory.use
import kotlin.experimental.and
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

    @Test
    fun `verify txout proofs`() {
        run {
            // this is a txout proof for tx 89ae0cca6a53d4339705c17766f6cafe2fc3c600453232c776664ef103008c5b

            val raw =
                Hex.decode("0000c0208d1459d7a99eb66ea054532c29771d39bba60c897314030000000000000000009fed1aefd92f59e35f1410570f90c0d5f43ab7ea58c7af6ecccef50c7c7b7ae3ed06d862afa70917308a412ecc0b00000cdfc60a77fdd548edf67c6a7a023a7d7b2a6b107a8b425b2328c2a4ed7621c65b22f578025d43c278f33514b5d3cdddafa89b5505b74fba4fdbe725a378d37d835b8c0003f14e6676c732324500c6c32ffecaf66677c1059733d4536aca0cae89913273ca64be4efcb44c86bc37b86ce17b1292b513de9c2f07b613c798966124ded1c92d32904a5928b940f4f11e9e75bff77f804e401947036ebd896acba889de0023490f45392a271d2bfbb8c0a912092c5d314d34c785a4c59dca160b5611b9151eaa500aa813b35d33f1d4d1bed3059349362f4dbffb1ad82f911e1d23ed9cf285084722c59f2947b87499f829fdf7edf4338292af047635b46b82e8e1e262b5f837b524359e2bc3572831e23862832b698da33b82ebcc28ce048e8b9d9061de2fadecd76ac3f6304f8c86f559564ef9aca03a8efe057b3da7fa3530e342f8422cdaa56349887e92ae22f040d90e135505c8bb12b91dd9f0c2413179a5ef770972389e6dea9a8cfb9d971d35bccf9959c7de570bd417ff1090d900ab0f8c037d7f00")
            val (header, matched) = Block.verifyTxOutProof(raw)
            assertEquals(header.hash, ByteVector32("000000000000000000030cbb70966693d2516ca868fb490582dcf3dec90250f1").reversed())
            assertEquals(matched, listOf(ByteVector32("89ae0cca6a53d4339705c17766f6cafe2fc3c600453232c776664ef103008c5b").reversed() to 2112))
        }
        run {
            // bitcoin-cli gettxoutproof '["f4ce56779e68877fecdc979c25b7ed7bfb8593afafa37b7b96e4e4dbd30ebcc8", "89ae0cca6a53d4339705c17766f6cafe2fc3c600453232c776664ef103008c5b", "77a07c36b284011296995dd6521ec788c381a3192d68edbb9eee6a1a01a5b95f"]'
            val raw = Hex.decode(
                "0000c0208d1459d7a99eb66ea054532c29771d39bba60c897314030000000000000000009fed1aefd92f59e35f1410570f90c0d5f43ab7ea58c7af6ecccef50c7c7b7ae3ed06d862afa70917308a412ecc0b000019dfc60a77fdd548edf67c6a7a023a7d7b2a6b107a8b425b2328c2a4ed7621c65b22f578025d43c278f33514b5d3cdddafa89b5505b74fba4fdbe725a378d37d835b8c0003f14e6676c732324500c6c32ffecaf66677c1059733d4536aca0cae89913273ca64be4efcb44c86bc37b86ce17b1292b513de9c2f07b613c798966124ded1c92d32904a5928b940f4f11e9e75bff77f804e401947036ebd896acba889de0023490f45392a271d2bfbb8c0a912092c5d314d34c785a4c59dca160b5611b9151eaa500aa813b35d33f1d4d1bed3059349362f4dbffb1ad82f911e1d23ed9cf285084722c59f2947b87499f829fdf7edf4338292af047635b46b82e8e1e262b5f837b524359e2bc3572831e23862832b698da33b82ebcc28ce048e8b9d9061de2fadecd76ac3f6304f8c86f559564ef9aca03a8efe057b3da7fa3530e342f8422cdaa56349887e92ae22f040d90e135505c8bb12b91dd9f0c2413179a5efa380fd0f292b2a3a8f80d06d0213573fbe6a0f7b3df11ceea069c1249d322697beb23d697b1e35cce2834426514ba111c8d728fe89231937c26dbc577fa242bf8127544db139078c43087b0ccee2806d76ffc08ae66480608c808812cc7c092ba1b2a54d89babd64d0ee6f644911643442d70d060e2e633dc4e6c668df6d80e325292348e9859218a8eb860ca006089d76fef266a33d2dfbb88abad72d022a93976e45cacaba7d7405dc48be530c84f961f503906aec983246c6629b07311661c8bc0ed3dbe4e4967b7ba3afaf9385fb7bedb7259c97dcec7f87689e7756cef4df4b51bfb7767c2dce8f3dd892442cf0e882f0e98572c6a1a705b25a9d73a8dde11543f5516ce7842aa15afd501ec97d2dc96f6b86f61e94d1a738c5917c5558715060d28d6c5ca778e614e3b28297c9846b5924920e3e65fb35016a3dfe525b5fb9a5011a6aee9ebbed682d19a381c388c71e52d65d9996120184b2367ca0774053b9d90fa400f6593a4049d3fa4ea8071ca0ebe868a3975e25811040cf65f4fe77d21f625d5723ed260ea9c6b4ad1be2ba6f9e9df43a6ef400cff571ab3c126591f066459a966e74e9f783d652be9d46af3bfde5995be2856c65509fb99d70077d7f80da6a5b00"
            )
            val (header, matched) = Block.verifyTxOutProof(raw)
            assertEquals(header.hash, ByteVector32("000000000000000000030cbb70966693d2516ca868fb490582dcf3dec90250f1").reversed())
            assertEquals(
                matched,
                listOf(
                    ByteVector32("89ae0cca6a53d4339705c17766f6cafe2fc3c600453232c776664ef103008c5b").reversed() to 2112,
                    ByteVector32("f4ce56779e68877fecdc979c25b7ed7bfb8593afafa37b7b96e4e4dbd30ebcc8").reversed() to 2990,
                    ByteVector32("77a07c36b284011296995dd6521ec788c381a3192d68edbb9eee6a1a01a5b95f").reversed() to 2997,
                )
            )
        }
        run {
            // bitcoin-cli gettxoutproof '["ecaff871e308d2e13a53c75c4976aeae49dfc9cd91a0e6c478e4ef561e2ebdaf","228e8bef644fdfbd60f26eda9df1ff910a28b4b0d315394f593300906b540980","cbdad80c2140191548a21885aa56a916c2ddc43bbb87d27c0b2434c6ad68dbaa"]'
            var raw = Hex.decode(
                "0000002051ac76bab033df05336c51eed091525aec9c12ea1e6c0700000000000000000033e8830654ba263225a013bc7af63a29e8b9da7f093beacabe0ee48974f62851ad7f6e5faa920e17201c2dc54104000012e008dd2119f24b941e97a9a17a6ba684f99999a8bf63f54d771d2df93098b3da3df20b78c761f58555a57cd8b073685680fe05a230bade66f031854a2ad7c561c341db5a05744eea6cb589bde17ba60c8bdafda1baf76eaeef19bbc695cda277afbd2e1e56efe478c4e6a091cdc9df49aeae76495cc7533ae1d208e371f8afec6f4991af6eff74e21a9563bfedcf3c7736c6921cda270c385e9def1e2465f0717370d6d27057b9491405071ae90395e5c5fdefc7759296287c19f9faecde9119bc0ac7eb0412de0ce63d8055c9b0b3e1128e80b29bba2ae2a1f3a6be8a72488d33bda3374730a5278c953630d316772287d9be24eaa2822bf3349894412409dfe8212ef1d3fc2a45f6b7dc6d1bddecb1e72b72d92dc0af682be1d1c2ba8878dafbeece4ef5d137a2285c8cd7975e006541592976722b82383f7c94ee2e8a8e558009546b900033594f3915d3b0b4280a91fff19dda6ef260bddf4f64ef8b8e224d9d26736c87209d8573abcaa66fa596420fb939a0910ca3d4c52f8373427236a4b5ddc77e1046806dd7c40aae3bf29e4f974717736c77e5459656658c205c700ced60a546470f5d8f344bd2645edc5a1da5229936cbbe655d12e364f344fe7934359e1c2f564e463fb142493d15c2e1a85d948d510bb63201ce4d495e67355a4d0bc04f8d5fe289ee49c6c031f6787c7d63eb3a4144ea1a13aeb717559fbeb418e07945c4b2c19c8d6f8930d79e9e264d3a989917766ea25bdcfb709948ff54aadb68adc634240b7cd287bb3bc4ddc216a956aa8518a248151940210cd8dacb067f755605ef0f"
            )
            val (header, matched) = Block.verifyTxOutProof(raw)
            assertEquals(header.hash, ByteVector32("0000000000000000000060e32d547b6ae2ded52aadbc6310808e4ae42b08cc6a").reversed())
            assertEquals(
                matched,
                listOf(
                    ByteVector32("ecaff871e308d2e13a53c75c4976aeae49dfc9cd91a0e6c478e4ef561e2ebdaf").reversed() to 28,
                    ByteVector32("228e8bef644fdfbd60f26eda9df1ff910a28b4b0d315394f593300906b540980").reversed() to 47,
                    ByteVector32("cbdad80c2140191548a21885aa56a916c2ddc43bbb87d27c0b2434c6ad68dbaa").reversed() to 1088
                )
            )
        }
    }
}