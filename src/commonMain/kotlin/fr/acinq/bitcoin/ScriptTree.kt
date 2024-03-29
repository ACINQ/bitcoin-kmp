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

import fr.acinq.bitcoin.io.ByteArrayOutput

/** Simple binary tree structure containing taproot spending scripts. */
public sealed class ScriptTree {
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
    }

    public data class Branch(val left: ScriptTree, val right: ScriptTree) : ScriptTree()

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
}
