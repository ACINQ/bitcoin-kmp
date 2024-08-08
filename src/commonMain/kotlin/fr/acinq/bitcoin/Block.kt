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
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.secp256k1.Hex
import kotlin.experimental.and
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

/** This is the double hash of a serialized block header. */
public data class BlockHash(@JvmField val value: ByteVector32) {
    public constructor(hash: ByteArray) : this(hash.byteVector32())
    public constructor(hash: String) : this(ByteVector32(hash))
    public constructor(blockId: BlockId) : this(blockId.value.reversed())

    override fun toString(): String = value.toString()
}

/** This contains the same data as [BlockHash], but encoded with the opposite endianness. */
public data class BlockId(@JvmField val value: ByteVector32) {
    public constructor(blockId: ByteArray) : this(blockId.byteVector32())
    public constructor(blockId: String) : this(ByteVector32(blockId))
    public constructor(hash: BlockHash) : this(hash.value.reversed())

    override fun toString(): String = value.toString()
}

/**
 * @param version           Block version information, based upon the software version creating this block
 * @param hashPreviousBlock The hash value of the previous block this particular block references.
 * @param hashMerkleRoot    The reference to a Merkle tree collection which is a hash of all transactions related to this block
 * @param time              A timestamp recording when this block was created (Will overflow in 2106[2])
 * @param bits              The calculated difficulty target being used for this block
 * @param nonce             The nonce used to generate this block… to allow variations of the header and compute different hashes
 */
public data class BlockHeader(
    @JvmField val version: Long,
    @JvmField val hashPreviousBlock: BlockHash,
    @JvmField val hashMerkleRoot: ByteVector32,
    @JvmField val time: Long,
    @JvmField val bits: Long,
    @JvmField val nonce: Long
) : BtcSerializable<BlockHeader> {
    @JvmField
    public val hash: BlockHash = BlockHash(Crypto.hash256(write(this)))

    @JvmField
    public val blockId: BlockId = BlockId(hash)

    public fun setVersion(input: Long): BlockHeader = this.copy(version = input)

    public fun setHashPreviousBlock(input: BlockHash): BlockHeader = this.copy(hashPreviousBlock = input)

    public fun setHashMerkleRoot(input: ByteVector32): BlockHeader = this.copy(hashMerkleRoot = input)

    public fun setTime(input: Long): BlockHeader = this.copy(time = input)

    public fun setBits(input: Long): BlockHeader = this.copy(bits = input)

    public fun setNonce(input: Long): BlockHeader = this.copy(nonce = input)

    public fun difficulty(): UInt256 {
        val (diff, neg, _) = UInt256.decodeCompact(bits)
        return if (neg) -diff else diff
    }

    /**
     *
     * @return the amount of work represented by this block's difficulty target, as displayed by bitcoin core
     */
    public fun blockProof(): UInt256 = blockProof(bits)

    /**
     * Proof of work: hash(header) <= target difficulty
     *
     * @return true if this block header validates its expected proof of work
     */
    public fun checkProofOfWork(): Boolean {
        val (target, _, _) = UInt256.decodeCompact(bits)
        val hash = UInt256(blockId.value.toByteArray())
        return hash <= target
    }

    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    public companion object : BtcSerializer<BlockHeader>() {
        override fun read(input: Input, protocolVersion: Long): BlockHeader {
            val version = uint32(input)
            val hashPreviousBlock = BlockHash(hash(input))
            val hashMerkleRoot = hash(input)
            val time = uint32(input)
            val bits = uint32(input)
            val nonce = uint32(input)
            return BlockHeader(
                version.toLong(),
                hashPreviousBlock,
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
            writeBytes(message.hashPreviousBlock.value, output)
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
        public fun getDifficulty(header: BlockHeader): UInt256 = header.difficulty()

        /**
         *
         * @param bits difficulty target
         * @return the amount of work represented by this difficulty target, as displayed
         *         by bitcoin core
         */
        @JvmStatic
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
        public fun checkProofOfWork(header: BlockHeader): Boolean = header.checkProofOfWork()

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
    @JvmStatic
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

public data class Block(@JvmField val header: BlockHeader, @JvmField val tx: List<Transaction>) {
    @JvmField
    val hash: BlockHash = header.hash

    @JvmField
    val blockId: BlockId = header.blockId

    /**
     * Proof of work: hash(block) <= target difficulty
     *
     * @return true if the input block validates its expected proof of work
     */
    public fun checkProofOfWork(): Boolean = BlockHeader.checkProofOfWork(header)

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
            require(message.header.hashMerkleRoot == MerkleTree.computeRoot(message.tx.map { it.hash.value })) { "invalid block:  merkle root mismatch" }
            require(message.tx.map { it.hash }.toSet().size == message.tx.size) { "invalid block: duplicate transactions" }
            message.tx.map { Transaction.validate(it) }
        }

        /**
         * Proof of work: hash(block) <= target difficulty
         *
         * @param block
         * @return true if the input block validates its expected proof of work
         */
        @JvmStatic
        public fun checkProofOfWork(block: Block): Boolean = block.checkProofOfWork()

        /**
         * Verify a tx inclusion proof (a merkle proof that a set of transactions are included in a given block)
         * Note that this method doesn't validate the header's proof of work.
         *
         * @param proof tx inclusion proof, in the format used by bitcoin core's 'verifytxoutproof' RPC call
         * @return a (block header, matched tx ids and positions in the block) tuple
         */
        @JvmStatic
        public fun verifyTxOutProof(proof: ByteArray): Pair<BlockHeader, List<Pair<ByteVector32, Int>>> {
            // a txout proof is generated for a given block and a given list of transactions, and contains a merkle proof that these transactions
            // were indeed in the block. The format of a proof is:
            // block header | number of transactions in the block | merkle node hashes | flag bits
            // a flag bit is set if the current node is one of the leaf tx for which this proof was generated or one of its ancestors
            // see https://en.bitcoin.it/wiki/BIP_0037#Partial_Merkle_branch_format for more details
            val header = BlockHeader.read(proof.take(80).toByteArray())
            val inputStream = ByteArrayInput(proof.drop(80).toByteArray())
            val txCount = uint32(inputStream).toInt()
            val hashes = readCollection(inputStream, { i, _ -> hash(i).byteVector32() }, null, Protocol.PROTOCOL_VERSION)
            val bits = script(inputStream)

            /**
             * @param bits array of bytes
             * @param pos position
             * @return the bit value in the input byte array at position `pos`
             */
            fun bit(bits: ByteArray, pos: Int): Boolean {
                val elt = bits[pos / 8]
                return (elt.and((1.shl(pos % 8)).toByte()) != 0.toByte())
            }

            /**
             * @param height height for which we want to know the width of the tree (0 is the bottom of the tree)
             * @return the width of a merkle tree at a given height
             */
            fun calcTreeWidth(height: Int): Int = (txCount + (1.shl(height)) - 1).shr(height)

            var bitsUsed = 0 // number of bits that we've used so far
            var hashUsed = 0 // number of hashes that we've used so far
            var matched: List<Pair<ByteVector32, Int>> = listOf() // list of (txids, index) that we've matched so far
            var height = 0 // current height

            // find the height of the tree (leaves are at height = 0)
            while (calcTreeWidth(height) > 1) {
                height++
            }

            // traverse the tree and update the list of matched txids and positions
            // return the hash of the node at (height, pos)
            fun traverseAndExtract(height: Int, pos: Int): ByteVector32 {
                // check if the current node is a tx for which we have a proof or one of its ancestors
                val parentOfMatch = bit(bits, bitsUsed++)
                return when {
                    height == 0 -> {
                        val hash = hashes[hashUsed++]
                        if (parentOfMatch) matched = matched + Pair(hash, pos)
                        hash
                    }
                    !parentOfMatch -> hashes[hashUsed++]
                    else -> {
                        // otherwise, descend into the subtrees to extract matched txids and hashes
                        val left = traverseAndExtract(height - 1, pos * 2)
                        val right = if ((pos * 2 + 1) < calcTreeWidth(height - 1)) {
                            val hash = traverseAndExtract(height - 1, pos * 2 + 1)
                            // The left and right branches should never be identical, as the transaction
                            // hashes covered by them must each be unique.
                            require(hash != left) { "invalid leaf hash" }
                            hash
                        } else {
                            // if we don't have enough leaves we duplicate the last one
                            left
                        }
                        // and combine them before returning
                        left.concat(right).sha256().sha256()
                    }
                }
            }

            val root = traverseAndExtract(height, 0)
            require(root == header.hashMerkleRoot) { "invalid merkle root: expected ${header.hashMerkleRoot.toHex()}, got ${root.toHex()}" }
            return Pair(header, matched)
        }

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
                    hashPreviousBlock = BlockHash(ByteVector32.Zeroes),
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
        public val Testnet3GenesisBlock: Block = LivenetGenesisBlock.copy(
            header = LivenetGenesisBlock.header.copy(time = 1296688602, nonce = 414098458)
        )

        @JvmField
        @Deprecated("testnet is the deprecated testnet3 network, use testnet3 explicitly", replaceWith = ReplaceWith("Block.Testnet3GenesisBlock", "fr.acinq.bitcoin.Block"))
        public val TestnetGenesisBlock: Block = Testnet3GenesisBlock

        @JvmField
        public val Testnet4GenesisBlock: Block = run {
            val script = listOf(
                OP_PUSHDATA(writeUInt32(486604799u)),
                OP_PUSHDATA(ByteVector("04")),
                OP_PUSHDATA("03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e".encodeToByteArray())
            )
            val scriptPubKey = listOf(
                OP_PUSHDATA(ByteVector("000000000000000000000000000000000000000000000000000000000000000000")),
                OP_CHECKSIG
            )
            Block(
                BlockHeader(
                    version = 1,
                    hashPreviousBlock = BlockHash(ByteVector32.Zeroes),
                    hashMerkleRoot = ByteVector32("7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e").reversed(),
                    time = 1714777860,
                    bits = 0x1d00ffff,
                    nonce = 393743547
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
        public val RegtestGenesisBlock: Block = LivenetGenesisBlock.copy(
            header = LivenetGenesisBlock.header.copy(
                bits = 0x207fffffL,
                nonce = 2,
                time = 1296688602
            )
        )

        @JvmField
        public val SignetGenesisBlock: Block = LivenetGenesisBlock.copy(
            header = LivenetGenesisBlock.header.copy(
                bits = 503543726,
                time = 1598918400,
                nonce = 52613770
            )
        )
    }
}