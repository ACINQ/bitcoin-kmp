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
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import kotlin.jvm.JvmStatic

/** Simple binary tree structure containing taproot spending scripts. */
public sealed class ScriptTree {
    // our own tree-based binary format
    public abstract fun write(output: Output): Output

    public fun write(): ByteArray {
        val output = ByteArrayOutput()
        write(output)
        return output.toByteArray()
    }

    // BIP373 binary format
    public abstract fun writeForPSbt(output: Output, level: Int): Output

    public fun writeForPsbt(): ByteArray {
        val output = ByteArrayOutput()
        writeForPSbt(output, 0)
        return output.toByteArray()
    }

    /**
     * Multiple spending scripts can be placed in the leaves of a taproot tree. When using one of those scripts to spend
     * funds, we only need to reveal that specific script and a merkle proof that it is a leaf of the tree.
     *
     * @param id id that isn't used in the hash, but can be used by the caller to reference specific scripts.
     * @param script serialized spending script.
     * @param leafVersion tapscript version.
     */
    public data class Leaf(val id: Int, val script: ByteVector, val leafVersion: Int) : ScriptTree() {
        public constructor(id: Int, script: List<ScriptElt>) : this(id, script, Script.TAPROOT_LEAF_TAPSCRIPT)
        public constructor(id: Int, script: List<ScriptElt>, leafVersion: Int) : this(id, Script.write(script).byteVector(), leafVersion)
        public constructor(id: Int, script: String, leafVersion: Int) : this(id, ByteVector.fromHex(script), leafVersion)

        public override fun write(output: Output): Output {
            output.write(0)
            BtcSerializer.writeVarint(id, output)
            BtcSerializer.writeScript(script, output)
            output.write(leafVersion)
            return output
        }

        override fun writeForPSbt(output: Output, level: Int): Output {
            // id is not persisted
            output.write(level)
            output.write(leafVersion)
            BtcSerializer.writeScript(script, output)
            return output
        }
    }

    public data class Branch(val left: ScriptTree, val right: ScriptTree) : ScriptTree() {
        public override fun write(output: Output): Output {
            output.write(1)
            left.write(output)
            right.write(output)
            return output
        }

        override fun writeForPSbt(output: Output, level: Int): Output {
            left.writeForPSbt(output, level + 1)
            right.writeForPSbt(output, level + 1)
            return output
        }

    }

    /** Compute the merkle root of the script tree. */
    public fun hash(): ByteVector32 = when (this) {
        is Leaf -> {
            val buffer = ByteArrayOutput()
            buffer.write(this.leafVersion)
            BtcSerializer.writeScript(this.script, buffer)
            Crypto.taggedHash(buffer.toByteArray(), "TapLeaf")
        }

        is Branch -> {
            val h1 = this.left.hash()
            val h2 = this.right.hash()
            val toHash = if (LexicographicalOrdering.isLessThan(h1, h2)) h1 + h2 else h2 + h1
            Crypto.taggedHash(toHash.toByteArray(), "TapBranch")
        }
    }

    /** Return the first script leaf with the corresponding id, if any. */
    public fun findScript(id: Int): Leaf? = when (this) {
        is Leaf -> if (this.id == id) this else null
        is Branch -> this.left.findScript(id) ?: this.right.findScript(id)
    }

    /**
     * Compute a merkle proof for the given script leaf.
     * This merkle proof is encoded for creating control blocks in taproot script path witnesses.
     * If the leaf doesn't belong to the script tree, this function will return null.
     */
    public fun merkleProof(leafHash: ByteVector32): ByteArray? {
        fun loop(tree: ScriptTree, proof: ByteArray): ByteArray? = when (tree) {
            is Leaf -> if (tree.hash() == leafHash) proof else null
            is Branch -> loop(tree.left, tree.right.hash().toByteArray() + proof) ?: loop(tree.right, tree.left.hash().toByteArray() + proof)
        }
        return loop(this, ByteArray(0))
    }

    public companion object {
        @JvmStatic
        public fun read(input: Input): ScriptTree = when (val tag = input.read()) {
            0 -> Leaf(BtcSerializer.varint(input).toInt(), BtcSerializer.script(input).byteVector(), input.read())
            1 -> Branch(read(input), read(input))
            else -> error("cannot deserialize script tree: invalid tag $tag")
        }

        @JvmStatic
        public fun read(input: ByteArray): ScriptTree = read(ByteArrayInput(input))

        internal fun readLeaves(input: Input, setIdToZero: Boolean = true): ArrayList<Pair<Int, ScriptTree>> {
            val leaves = arrayListOf<Pair<Int, ScriptTree>>()
            var id = 0
            while (input.availableBytes > 0) {
                val depth = input.read()
                val leafVersion = input.read()
                val script = BtcSerializer.script(input).byteVector()
                leaves.add(Pair(depth, Leaf(if (setIdToZero) 0 else id++, script, leafVersion)))
            }
            return leaves
        }

        internal fun merge(nodes: ArrayList<Pair<Int, ScriptTree>>): Boolean {
            if (nodes.size > 1) {
                var i = 0
                while (i < nodes.size - 1) {
                    if (nodes[i].first == nodes[i + 1].first) {
                        val node = Pair(nodes[i].first - 1, Branch(nodes[i].second, nodes[i + 1].second))
                        nodes[i] = node
                        nodes.removeAt(i + 1)
                        return true
                    } else i++
                }
            }
            return false
        }

        @JvmStatic
        public fun readFromPsbt(input: Input, setIdToZero: Boolean = true): ScriptTree {
            val leaves = readLeaves(input, setIdToZero)
            while (merge(leaves)) {
                // keep on merging
            }
            return when (leaves.size) {
                1 -> leaves[0].second
                2 -> Branch(leaves[0].second, leaves[1].second)
                else -> error("cannot merge $leaves")
            }
        }
    }
}
