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

import fr.acinq.secp256k1.Hex
import kotlin.test.*

class BlockTestsCommon {
    private val blockData = TestHelpers.readResourceAsByteArray("block1.dat")

    @Test
    fun `read blocks`() {
        val block = Block.read(blockData)
        assertTrue(Block.checkProofOfWork(block))

        assertEquals(MerkleTree.computeRoot(block.tx.map { it.hash.value }), block.header.hashMerkleRoot)

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
    fun `serialize and deserialize block headers`() {
        // The following are mainnet block headers for blocks 784900 and 784901.
        val serialized784900 = ByteVector("0020a1309ea246510ac18e4bf1e40d7534e0e34ccc9af28c24a402000000000000000000bb5c749cd2700dbfb944acaefdc5af88e85b12b2300a80edf0d8d51cf00149c709333564b2e0051776140ae0")
        val header784900 = BlockHeader.read(serialized784900.bytes)
        val serialized784901 = ByteVector("00602f2ae7c9e1422e2782ea47a06a1e646a7ed61abefd11fe1102000000000000000000b6695a665e4f1b444770bb8e6224cce3ee4c74e031cbaf432981718b7a0c53e42e343564b2e00517275e5cf9")
        val header784901 = BlockHeader.read(serialized784901.bytes)
        assertEquals(header784901.hashPreviousBlock, header784900.hash)
        assertEquals(serialized784900, BlockHeader.write(header784900).byteVector())
        assertEquals(serialized784901, BlockHeader.write(header784901).byteVector())
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
            hashPreviousBlock = BlockHash(ByteVector32.Zeroes),
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
            // transaction included in mainnet block 745762
            // bitcoin-cli gettxoutproof '["89ae0cca6a53d4339705c17766f6cafe2fc3c600453232c776664ef103008c5b"]'
            val raw = Hex.decode(
                "0000c0208d1459d7a99eb66ea054532c29771d39bba60c897314030000000000000000009fed1aefd92f59e35f1410570f90c0d5f43ab7ea58c7af6ecccef50c7c7b7ae3ed06d862afa70917308a412ecc0b00000cdfc60a77fdd548edf67c6a7a023a7d7b2a6b107a8b425b2328c2a4ed7621c65b22f578025d43c278f33514b5d3cdddafa89b5505b74fba4fdbe725a378d37d835b8c0003f14e6676c732324500c6c32ffecaf66677c1059733d4536aca0cae89913273ca64be4efcb44c86bc37b86ce17b1292b513de9c2f07b613c798966124ded1c92d32904a5928b940f4f11e9e75bff77f804e401947036ebd896acba889de0023490f45392a271d2bfbb8c0a912092c5d314d34c785a4c59dca160b5611b9151eaa500aa813b35d33f1d4d1bed3059349362f4dbffb1ad82f911e1d23ed9cf285084722c59f2947b87499f829fdf7edf4338292af047635b46b82e8e1e262b5f837b524359e2bc3572831e23862832b698da33b82ebcc28ce048e8b9d9061de2fadecd76ac3f6304f8c86f559564ef9aca03a8efe057b3da7fa3530e342f8422cdaa56349887e92ae22f040d90e135505c8bb12b91dd9f0c2413179a5ef770972389e6dea9a8cfb9d971d35bccf9959c7de570bd417ff1090d900ab0f8c037d7f00"
            )
            val (header, matched) = Block.verifyTxOutProof(raw)
            assertEquals(header.blockId, BlockId("000000000000000000030cbb70966693d2516ca868fb490582dcf3dec90250f1"))
            assertTrue(BlockHeader.checkProofOfWork(header))
            assertEquals(matched, listOf(ByteVector32("89ae0cca6a53d4339705c17766f6cafe2fc3c600453232c776664ef103008c5b").reversed() to 2112))
        }
        run {
            // transactions included in mainnet block 745762
            // bitcoin-cli gettxoutproof '["f4ce56779e68877fecdc979c25b7ed7bfb8593afafa37b7b96e4e4dbd30ebcc8", "89ae0cca6a53d4339705c17766f6cafe2fc3c600453232c776664ef103008c5b", "77a07c36b284011296995dd6521ec788c381a3192d68edbb9eee6a1a01a5b95f"]'
            val raw = Hex.decode(
                "0000c0208d1459d7a99eb66ea054532c29771d39bba60c897314030000000000000000009fed1aefd92f59e35f1410570f90c0d5f43ab7ea58c7af6ecccef50c7c7b7ae3ed06d862afa70917308a412ecc0b000019dfc60a77fdd548edf67c6a7a023a7d7b2a6b107a8b425b2328c2a4ed7621c65b22f578025d43c278f33514b5d3cdddafa89b5505b74fba4fdbe725a378d37d835b8c0003f14e6676c732324500c6c32ffecaf66677c1059733d4536aca0cae89913273ca64be4efcb44c86bc37b86ce17b1292b513de9c2f07b613c798966124ded1c92d32904a5928b940f4f11e9e75bff77f804e401947036ebd896acba889de0023490f45392a271d2bfbb8c0a912092c5d314d34c785a4c59dca160b5611b9151eaa500aa813b35d33f1d4d1bed3059349362f4dbffb1ad82f911e1d23ed9cf285084722c59f2947b87499f829fdf7edf4338292af047635b46b82e8e1e262b5f837b524359e2bc3572831e23862832b698da33b82ebcc28ce048e8b9d9061de2fadecd76ac3f6304f8c86f559564ef9aca03a8efe057b3da7fa3530e342f8422cdaa56349887e92ae22f040d90e135505c8bb12b91dd9f0c2413179a5efa380fd0f292b2a3a8f80d06d0213573fbe6a0f7b3df11ceea069c1249d322697beb23d697b1e35cce2834426514ba111c8d728fe89231937c26dbc577fa242bf8127544db139078c43087b0ccee2806d76ffc08ae66480608c808812cc7c092ba1b2a54d89babd64d0ee6f644911643442d70d060e2e633dc4e6c668df6d80e325292348e9859218a8eb860ca006089d76fef266a33d2dfbb88abad72d022a93976e45cacaba7d7405dc48be530c84f961f503906aec983246c6629b07311661c8bc0ed3dbe4e4967b7ba3afaf9385fb7bedb7259c97dcec7f87689e7756cef4df4b51bfb7767c2dce8f3dd892442cf0e882f0e98572c6a1a705b25a9d73a8dde11543f5516ce7842aa15afd501ec97d2dc96f6b86f61e94d1a738c5917c5558715060d28d6c5ca778e614e3b28297c9846b5924920e3e65fb35016a3dfe525b5fb9a5011a6aee9ebbed682d19a381c388c71e52d65d9996120184b2367ca0774053b9d90fa400f6593a4049d3fa4ea8071ca0ebe868a3975e25811040cf65f4fe77d21f625d5723ed260ea9c6b4ad1be2ba6f9e9df43a6ef400cff571ab3c126591f066459a966e74e9f783d652be9d46af3bfde5995be2856c65509fb99d70077d7f80da6a5b00"
            )
            val (header, matched) = Block.verifyTxOutProof(raw)
            assertEquals(header.blockId, BlockId("000000000000000000030cbb70966693d2516ca868fb490582dcf3dec90250f1"))
            assertTrue(BlockHeader.checkProofOfWork(header))
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
            // transactions included in mainnet block 650000
            // bitcoin-cli gettxoutproof '["ecaff871e308d2e13a53c75c4976aeae49dfc9cd91a0e6c478e4ef561e2ebdaf","228e8bef644fdfbd60f26eda9df1ff910a28b4b0d315394f593300906b540980","cbdad80c2140191548a21885aa56a916c2ddc43bbb87d27c0b2434c6ad68dbaa"]'
            val raw = Hex.decode(
                "0000002051ac76bab033df05336c51eed091525aec9c12ea1e6c0700000000000000000033e8830654ba263225a013bc7af63a29e8b9da7f093beacabe0ee48974f62851ad7f6e5faa920e17201c2dc54104000012e008dd2119f24b941e97a9a17a6ba684f99999a8bf63f54d771d2df93098b3da3df20b78c761f58555a57cd8b073685680fe05a230bade66f031854a2ad7c561c341db5a05744eea6cb589bde17ba60c8bdafda1baf76eaeef19bbc695cda277afbd2e1e56efe478c4e6a091cdc9df49aeae76495cc7533ae1d208e371f8afec6f4991af6eff74e21a9563bfedcf3c7736c6921cda270c385e9def1e2465f0717370d6d27057b9491405071ae90395e5c5fdefc7759296287c19f9faecde9119bc0ac7eb0412de0ce63d8055c9b0b3e1128e80b29bba2ae2a1f3a6be8a72488d33bda3374730a5278c953630d316772287d9be24eaa2822bf3349894412409dfe8212ef1d3fc2a45f6b7dc6d1bddecb1e72b72d92dc0af682be1d1c2ba8878dafbeece4ef5d137a2285c8cd7975e006541592976722b82383f7c94ee2e8a8e558009546b900033594f3915d3b0b4280a91fff19dda6ef260bddf4f64ef8b8e224d9d26736c87209d8573abcaa66fa596420fb939a0910ca3d4c52f8373427236a4b5ddc77e1046806dd7c40aae3bf29e4f974717736c77e5459656658c205c700ced60a546470f5d8f344bd2645edc5a1da5229936cbbe655d12e364f344fe7934359e1c2f564e463fb142493d15c2e1a85d948d510bb63201ce4d495e67355a4d0bc04f8d5fe289ee49c6c031f6787c7d63eb3a4144ea1a13aeb717559fbeb418e07945c4b2c19c8d6f8930d79e9e264d3a989917766ea25bdcfb709948ff54aadb68adc634240b7cd287bb3bc4ddc216a956aa8518a248151940210cd8dacb067f755605ef0f"
            )
            val (header, matched) = Block.verifyTxOutProof(raw)
            assertEquals(header.blockId, BlockId("0000000000000000000060e32d547b6ae2ded52aadbc6310808e4ae42b08cc6a"))
            assertTrue(BlockHeader.checkProofOfWork(header))
            assertEquals(
                matched,
                listOf(
                    ByteVector32("ecaff871e308d2e13a53c75c4976aeae49dfc9cd91a0e6c478e4ef561e2ebdaf").reversed() to 28,
                    ByteVector32("228e8bef644fdfbd60f26eda9df1ff910a28b4b0d315394f593300906b540980").reversed() to 47,
                    ByteVector32("cbdad80c2140191548a21885aa56a916c2ddc43bbb87d27c0b2434c6ad68dbaa").reversed() to 1088
                )
            )
        }
        run {
            // This is a full merkle tree (values are truncated to 7 chars for readability).
            // Note that transaction merkle trees in bitcoin are always balanced: if the number of transactions isn't a power of two,
            // we simply repeat the last element until we reach a power of two.
            //
            //                                     b6d2fa4
            //                                        |
            //                    +-------------------+-------------------+
            //                    |                                       |
            //                 00b1add                                 c0ccfa8
            //                    |                                       |
            //          +---------+---------+                   +---------+---------+
            //          |                   |                   |                   |
            //       9d264d8             5f0e0f5             4a4be1b             d8b41f8
            //          |                   |                   |                   |
            //     +----+---+          +----+----+         +----+----+         +----+----+
            //     |        |          |         |         |         |         |         |
            //  677c554   380545d   aa882a5   b2dd988   d2541dd   dab0f7e   ca8823f   45de35e
            //
            // We create a partial merkle tree for a single transaction (b2dd988):
            //
            //                                    b6d2fa4:1
            //                                        |
            //                    +-------------------+-------------------+
            //                    |                                       |
            //                00b1add:1                                c0ccfa8:0
            //                    |
            //          +---------+---------+
            //          |                   |
            //      9d264d8:0           5f0e0f5:1
            //                              |
            //                         +----+----+
            //                         |         |
            //                     aa882a5:0  b2dd988:1
            //
            // We build the serialized proof by doing a DFS and appending flags and leaves (see https://en.bitcoin.it/wiki/BIP_0037#Partial_Merkle_branch_format):
            // hashes = [9d264d8,aa882a5,b2dd988,c0ccfa8] flags = [1,1,0,1,0,1,0] padded_flags = 00101011
            //
            // We create a partial merkle tree for multiple transactions:
            //
            //                                    b6d2fa4:1
            //                                        |
            //                    +-------------------+-------------------+
            //                    |                                       |
            //                00b1add:1                               c0ccfa8:1
            //                    |                                       |
            //          +---------+---------+                   +---------+---------+
            //          |                   |                   |                   |
            //      9d264d8:1           5f0e0f5:0           4a4be1b:1           d8b41f8:1
            //          |                                       |                   |
            //     +----+---+                              +----+----+         +----+----+
            //     |        |                              |         |         |         |
            // 677c554:1 380545d:0                     d2541dd:1 dab0f7e:1 ca8823f:0 45de35e:1
            //
            // We build the serialized proof:
            // hashes = [677c554,380545d,5f0e0f5,d2541dd,dab0f7e,ca8823f,45de35e] flags = [1,1,1,1,0,0,1,1,1,1,1,0,1] padded_flags = 0001011111001111
            val txIds = listOf(
                ByteVector32("677c5545203f1c91b26b6a50536affdbaa54b108d494c8914f0e3e4a54f56f42"),
                ByteVector32("380545da8594ac4e7ce7db07fa1e8e7c0246429b4e1f63e8d421c384e6e4dfd9"),
                ByteVector32("aa882a5c1e057d7b9f2087dd2732799ff99fc6888510844e35cb80cd9b761a6a"),
                ByteVector32("b2dd988e75e4c368a333c557fd041c8faf3d2ba22274c4885c72f83f9a9fd0da"),
                ByteVector32("d2541ddfb40e7c70ac3c08821304807be843add33e0053a5f3186cc009387502"),
                ByteVector32("dab0f7e87567268ad0ec62158d9f7891b5191fc3ec3dc9b8b34958b95fee8226"),
                ByteVector32("ca8823ff4e3ca15eb20cda3ecb74ee65c6c0190a748f89637aa4509913927c1a"),
                ByteVector32("45de35e1b594f1b8baf4574a3eb3321b890c199a3dfdd0ccbca33160af0502c8"),
            )
            val parents = listOf(
                ByteVector32("9d264d87791e6fab369f676dcaac3230686a2d1a2d1f5f9420ef0504d4966658"),
                ByteVector32("5f0e0f5d0debf87f4c3f49ce940ab301ec2d7c7197a425403588e7c8e98f24f8"),
                ByteVector32("4a4be1b946fc09b79ac14690b6857887299f6717cd1045918d419b3e9f123bce"),
                ByteVector32("d8b41f8c74451aa81c4a732a6a7c1532113cf17bb64990e66fde3f2f9e7ee9e9"),
            )
            parents.forEachIndexed { i, h -> assertContentEquals(h.bytes, Crypto.hash256(txIds[2 * i].toByteArray() + txIds[2 * i + 1].toByteArray())) }
            val grandParents = listOf(
                ByteVector32("00b1adde6495559962cc1c6956ee7d1a44dee99a3bd5050be5e952e0c05fcb98"),
                ByteVector32("c0ccfa8328a42684ec02ff66a73d6efa1fc054bc439ee42fe76103a4369efcb0"),
            )
            grandParents.forEachIndexed { i, h -> assertContentEquals(h.bytes, Crypto.hash256(parents[2 * i].toByteArray() + parents[2 * i + 1].toByteArray())) }
            val root = ByteVector32("b6d2fa4051be265e682028e4dab1574375bb971a9ad86fde30dbfbca64ea20ab")
            assertContentEquals(root.bytes, Crypto.hash256(grandParents[0].toByteArray() + grandParents[1].toByteArray()))
            // The serialized proof format is:
            //  - block header (80 bytes)
            //  - transaction count (4 bytes)
            //  - number of node hashes (varint)
            //  - node hashes
            //  - number of flag bytes (varint)
            //  - flags (little endian)
            run {
                val singleTxProof = Hex.decode(
                    "000000000000000000000000000000000000000000000000000000000000000000000000b6d2fa4051be265e682028e4dab1574375bb971a9ad86fde30dbfbca64ea20ab000000000000000000000000 08000000 049d264d87791e6fab369f676dcaac3230686a2d1a2d1f5f9420ef0504d4966658aa882a5c1e057d7b9f2087dd2732799ff99fc6888510844e35cb80cd9b761a6ab2dd988e75e4c368a333c557fd041c8faf3d2ba22274c4885c72f83f9a9fd0dac0ccfa8328a42684ec02ff66a73d6efa1fc054bc439ee42fe76103a4369efcb0 012b"
                )
                val (header, matched) = Block.verifyTxOutProof(singleTxProof)
                assertEquals(header.hashMerkleRoot, root)
                assertEquals(
                    matched,
                    listOf(ByteVector32("b2dd988e75e4c368a333c557fd041c8faf3d2ba22274c4885c72f83f9a9fd0da") to 3)
                )
            }
            run {
                val manyTxsProof = Hex.decode(
                    "000000000000000000000000000000000000000000000000000000000000000000000000b6d2fa4051be265e682028e4dab1574375bb971a9ad86fde30dbfbca64ea20ab000000000000000000000000 08000000 07677c5545203f1c91b26b6a50536affdbaa54b108d494c8914f0e3e4a54f56f42380545da8594ac4e7ce7db07fa1e8e7c0246429b4e1f63e8d421c384e6e4dfd95f0e0f5d0debf87f4c3f49ce940ab301ec2d7c7197a425403588e7c8e98f24f8d2541ddfb40e7c70ac3c08821304807be843add33e0053a5f3186cc009387502dab0f7e87567268ad0ec62158d9f7891b5191fc3ec3dc9b8b34958b95fee8226ca8823ff4e3ca15eb20cda3ecb74ee65c6c0190a748f89637aa4509913927c1a45de35e1b594f1b8baf4574a3eb3321b890c199a3dfdd0ccbca33160af0502c8 02cf17"
                )
                val (header, matched) = Block.verifyTxOutProof(manyTxsProof)
                assertEquals(header.hashMerkleRoot, root)
                assertEquals(
                    matched,
                    listOf(
                        ByteVector32("677c5545203f1c91b26b6a50536affdbaa54b108d494c8914f0e3e4a54f56f42") to 0,
                        ByteVector32("d2541ddfb40e7c70ac3c08821304807be843add33e0053a5f3186cc009387502") to 4,
                        ByteVector32("dab0f7e87567268ad0ec62158d9f7891b5191fc3ec3dc9b8b34958b95fee8226") to 5,
                        ByteVector32("45de35e1b594f1b8baf4574a3eb3321b890c199a3dfdd0ccbca33160af0502c8") to 7,
                    ),
                )
            }
        }
        run {
            // This is the same proof as the previous test case, but with a different merkle root in the header.
            val merkleRootMismatch = Hex.decode(
                "0000000000000000000000000000000000000000000000000000000000000000000000009a9eb612675ed156127f414b9bf96525d8b23da9e65d2c84da197f8f71ccc6c0000000000000000000000000 08000000 07677c5545203f1c91b26b6a50536affdbaa54b108d494c8914f0e3e4a54f56f42380545da8594ac4e7ce7db07fa1e8e7c0246429b4e1f63e8d421c384e6e4dfd95f0e0f5d0debf87f4c3f49ce940ab301ec2d7c7197a425403588e7c8e98f24f8d2541ddfb40e7c70ac3c08821304807be843add33e0053a5f3186cc009387502dab0f7e87567268ad0ec62158d9f7891b5191fc3ec3dc9b8b34958b95fee8226ca8823ff4e3ca15eb20cda3ecb74ee65c6c0190a748f89637aa4509913927c1a45de35e1b594f1b8baf4574a3eb3321b890c199a3dfdd0ccbca33160af0502c8 02cf17"
            )
            assertFails { Block.verifyTxOutProof(merkleRootMismatch) }
            // This is the same proof as the previous test case, but with the last two node hashes inverted.
            val invalidNodeHash = Hex.decode(
                "000000000000000000000000000000000000000000000000000000000000000000000000b6d2fa4051be265e682028e4dab1574375bb971a9ad86fde30dbfbca64ea20ab000000000000000000000000 08000000 07677c5545203f1c91b26b6a50536affdbaa54b108d494c8914f0e3e4a54f56f42380545da8594ac4e7ce7db07fa1e8e7c0246429b4e1f63e8d421c384e6e4dfd95f0e0f5d0debf87f4c3f49ce940ab301ec2d7c7197a425403588e7c8e98f24f8d2541ddfb40e7c70ac3c08821304807be843add33e0053a5f3186cc009387502dab0f7e87567268ad0ec62158d9f7891b5191fc3ec3dc9b8b34958b95fee822645de35e1b594f1b8baf4574a3eb3321b890c199a3dfdd0ccbca33160af0502c8ca8823ff4e3ca15eb20cda3ecb74ee65c6c0190a748f89637aa4509913927c1a 02cf17"
            )
            assertFails { Block.verifyTxOutProof(invalidNodeHash) }
            // This is the same proof as the previous test case, but with invalid bit flags.
            val invalidBits = Hex.decode(
                "000000000000000000000000000000000000000000000000000000000000000000000000b6d2fa4051be265e682028e4dab1574375bb971a9ad86fde30dbfbca64ea20ab000000000000000000000000 08000000 07677c5545203f1c91b26b6a50536affdbaa54b108d494c8914f0e3e4a54f56f42380545da8594ac4e7ce7db07fa1e8e7c0246429b4e1f63e8d421c384e6e4dfd95f0e0f5d0debf87f4c3f49ce940ab301ec2d7c7197a425403588e7c8e98f24f8d2541ddfb40e7c70ac3c08821304807be843add33e0053a5f3186cc009387502dab0f7e87567268ad0ec62158d9f7891b5191fc3ec3dc9b8b34958b95fee8226ca8823ff4e3ca15eb20cda3ecb74ee65c6c0190a748f89637aa4509913927c1a45de35e1b594f1b8baf4574a3eb3321b890c199a3dfdd0ccbca33160af0502c8 02ab17"
            )
            assertFails { Block.verifyTxOutProof(invalidBits) }
            // This is the same proof as the previous test case, but with the last node hash missing.
            val missingNodeHash = Hex.decode(
                "000000000000000000000000000000000000000000000000000000000000000000000000b6d2fa4051be265e682028e4dab1574375bb971a9ad86fde30dbfbca64ea20ab000000000000000000000000 08000000 06677c5545203f1c91b26b6a50536affdbaa54b108d494c8914f0e3e4a54f56f42380545da8594ac4e7ce7db07fa1e8e7c0246429b4e1f63e8d421c384e6e4dfd95f0e0f5d0debf87f4c3f49ce940ab301ec2d7c7197a425403588e7c8e98f24f8d2541ddfb40e7c70ac3c08821304807be843add33e0053a5f3186cc009387502dab0f7e87567268ad0ec62158d9f7891b5191fc3ec3dc9b8b34958b95fee8226ca8823ff4e3ca15eb20cda3ecb74ee65c6c0190a748f89637aa4509913927c1a 02cf17"
            )
            assertFails { Block.verifyTxOutProof(missingNodeHash) }
        }
    }
}