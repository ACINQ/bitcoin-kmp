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

import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.secp256k1.Hex
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

/**
 *
 * @param version           Block version information, based upon the software version creating this block
 * @param hashPreviousBlock The hash value of the previous block this particular block references. Please not that
 *                          this hash is not reversed (as opposed to Block.hash)
 * @param hashMerkleRoot    The reference to a Merkle tree collection which is a hash of all transactions related to this block
 * @param time              A timestamp recording when this block was created (Will overflow in 2106[2])
 * @param bits              The calculated difficulty target being used for this block
 * @param nonce             The nonce used to generate this block… to allow variations of the header and compute different hashes
 */
@OptIn(ExperimentalUnsignedTypes::class)
public data class BlockHeader(
    @JvmField val version: Long,
    @JvmField val hashPreviousBlock: ByteVector32,
    @JvmField val hashMerkleRoot: ByteVector32,
    @JvmField val time: Long,
    @JvmField val bits: Long,
    @JvmField val nonce: Long
) : BtcSerializable<BlockHeader> {
    @JvmField
    public val hash: ByteVector32 = ByteVector32(Crypto.hash256(write(this)))

    @JvmField
    public val blockId: ByteVector32 = hash.reversed()

    public fun setVersion(input: Long): BlockHeader = this.copy(version = input)

    public fun setHashPreviousBlock(input: ByteVector32): BlockHeader = this.copy(hashPreviousBlock = input)

    public fun setHashMerkleRoot(input: ByteVector32): BlockHeader = this.copy(hashMerkleRoot = input)

    public fun setTime(input: Long): BlockHeader = this.copy(time = input)

    public fun setBits(input: Long): BlockHeader = this.copy(bits = input)

    public fun setNonce(input: Long): BlockHeader = this.copy(nonce = input)

    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    public companion object : BtcSerializer<BlockHeader>() {
        override fun read(input: Input, protocolVersion: Long): BlockHeader {
            val version = uint32(input)
            val hashPreviousBlock = hash(input)
            val hashMerkleRoot = hash(input)
            val time = uint32(input)
            val bits = uint32(input)
            val nonce = uint32(input)
            return BlockHeader(
                version.toLong(),
                hashPreviousBlock.byteVector32(),
                hashMerkleRoot.byteVector32(),
                time.toLong(),
                bits.toLong(),
                nonce.toLong()
            )
        }

        @JvmStatic
        override fun read(input: String): BlockHeader {
            return super.read(input)
        }

        @JvmStatic
        override fun read(input: ByteArray): BlockHeader {
            return super.read(input)
        }

        override fun write(message: BlockHeader, output: Output, protocolVersion: Long) {
            writeUInt32(message.version.toUInt(), output)
            writeBytes(message.hashPreviousBlock, output)
            writeBytes(message.hashMerkleRoot, output)
            writeUInt32(message.time.toUInt(), output)
            writeUInt32(message.bits.toUInt(), output)
            writeUInt32(message.nonce.toUInt(), output)
        }

        @JvmStatic
        override fun write(message: BlockHeader): ByteArray {
            return super.write(message)
        }

        @JvmStatic
        @OptIn(ExperimentalUnsignedTypes::class)
        public fun getDifficulty(header: BlockHeader): UInt256 {
            val (diff, neg, _) = UInt256.decodeCompact(header.bits)
            return if (neg) -diff else diff
        }

        /**
         *
         * @param bits difficulty target
         * @return the amount of work represented by this difficulty target, as displayed
         *         by bitcoin core
         */
        @JvmStatic
        @OptIn(ExperimentalUnsignedTypes::class)
        public fun blockProof(bits: Long): UInt256 {
            val (target, negative, overflow) = UInt256.decodeCompact(bits)
            return if (target == UInt256.Zero || negative || overflow) UInt256.Zero else {
                //  (~bnTarget / (bnTarget + 1)) + 1;
                val work = target.inv()
                work /= target.inc()
                work.inc()
            }
        }

        @JvmStatic
        public fun blockProof(header: BlockHeader): UInt256 = blockProof(header.bits)

        /**
         * Proof of work: hash(header) <= target difficulty
         *
         * @param header block header
         * @return true if the input block header validates its expected proof of work
         */
        @JvmStatic
        public fun checkProofOfWork(header: BlockHeader): Boolean {
            val (target, _, _) = UInt256.decodeCompact(header.bits)
            val hash = UInt256(header.blockId.toByteArray())
            return hash <= target
        }

        @JvmStatic
        public fun calculateNextWorkRequired(lastHeader: BlockHeader, lastRetargetTime: Long): Long {
            var actualTimespan = lastHeader.time - lastRetargetTime
            val targetTimespan = 14 * 24 * 60 * 60L // two weeks
            if (actualTimespan < targetTimespan / 4) actualTimespan = targetTimespan / 4
            if (actualTimespan > targetTimespan * 4) actualTimespan = targetTimespan * 4

            var (target, isnegative, overflow) = UInt256.decodeCompact(lastHeader.bits)
            require(!isnegative)
            require(!overflow)
            target *= UInt256(actualTimespan)
            target /= UInt256(targetTimespan)

            val powLimit = UInt256(Hex.decode("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
            if (target > powLimit) target = powLimit
            return target.encodeCompact(false)
        }
    }

    override fun serializer(): BtcSerializer<BlockHeader> = Companion
}

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
 */
public object MerkleTree {
    public tailrec fun computeRoot(tree: List<ByteVector32>): ByteVector32 {
        return when {
            tree.size == 1 -> tree[0]
            (tree.size % 2) != 0 -> computeRoot(tree + listOf(tree.last())) // append last element again
            else -> {
                val tree1 = mutableListOf<ByteVector32>()
                for (i in 0 until (tree.size / 2)) {
                    val hash = Crypto.hash256(tree[2 * i].toByteArray() + tree[2 * i + 1].toByteArray())
                    tree1.add(hash.byteVector32())
                }
                computeRoot(tree1.toList())
            }
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class, ExperimentalStdlibApi::class)
public data class Block(@JvmField val header: BlockHeader, @JvmField val tx: List<Transaction>) {
    @JvmField
    val hash: ByteVector32 = header.hash

    @JvmField
    val blockId: ByteVector32 = hash.reversed()

    public companion object : BtcSerializer<Block>() {
        override fun write(message: Block, out: Output, protocolVersion: Long) {
            BlockHeader.write(message.header, out)
            writeCollection(message.tx, out, Transaction, protocolVersion)
        }

        @JvmStatic
        override fun write(message: Block): ByteArray {
            return super.write(message)
        }

        override fun read(input: Input, protocolVersion: Long): Block {
            val raw = bytes(input, 80)
            val header = BlockHeader.read(raw)
            return Block(header, readCollection(input, Transaction, protocolVersion))
        }

        @JvmStatic
        override fun read(input: String): Block {
            return super.read(input)
        }

        @JvmStatic
        override fun read(input: ByteArray): Block {
            return super.read(input)
        }

        @JvmStatic
        override fun validate(message: Block) {
            BlockHeader.validate(message.header)
            require(message.header.hashMerkleRoot == MerkleTree.computeRoot(message.tx.map { it.hash })) { "invalid block:  merkle root mismatch" }
            require(message.tx.map { it.hash }.toSet().size == message.tx.size) { "invalid block: duplicate transactions" }
            message.tx.map { Transaction.validate(it) }
        }

        /**
         * Proof of work: hash(block) <= target difficulty
         *
         * @param block
         * @return true if the input block validates its expected proof of work
         */
        public fun checkProofOfWork(block: Block): Boolean = BlockHeader.checkProofOfWork(block.header)

        // genesis blocks
        @JvmField
        public val LivenetGenesisBlock: Block = run {
            val script = listOf(
                OP_PUSHDATA(writeUInt32(486604799u)),
                OP_PUSHDATA(ByteVector("04")),
                OP_PUSHDATA("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".encodeToByteArray())
            )
            val scriptPubKey = listOf(
                OP_PUSHDATA(ByteVector("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")),
                OP_CHECKSIG
            )
            Block(
                BlockHeader(
                    version = 1,
                    hashPreviousBlock = ByteVector32.Zeroes,
                    hashMerkleRoot = ByteVector32("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"),
                    time = 1231006505,
                    bits = 0x1d00ffff,
                    nonce = 2083236893
                ),
                listOf(
                    Transaction(
                        version = 1,
                        txIn = listOf(TxIn.coinbase(script)),
                        txOut = listOf(TxOut(amount = 5000000000.toSatoshi(), publicKeyScript = scriptPubKey)),
                        lockTime = 0
                    )
                )
            )
        }

        @JvmField
        public val TestnetGenesisBlock: Block = LivenetGenesisBlock.copy(
            header = LivenetGenesisBlock.header.copy(time = 1296688602, nonce = 414098458)
        )

        @JvmField
        public val RegtestGenesisBlock: Block = LivenetGenesisBlock.copy(
            header = LivenetGenesisBlock.header.copy(
                bits = 0x207fffffL,
                nonce = 2,
                time = 1296688602
            )
        )

        @JvmField
        public val SegnetGenesisBlock: Block = LivenetGenesisBlock.copy(
            header = LivenetGenesisBlock.header.copy(
                bits = 503447551,
                time = 1452831101,
                nonce = 0
            )
        )

    }
}