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
import kotlin.jvm.JvmStatic

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

    /**
     * @param leafHash target leaf hash
     * @return a merkle proof for the target leaf hash, or null if it cannot be found in the tree
     */
    public fun merkleProof(leafHash: ByteVector32): ByteArray? = merkleProof(this, leafHash)

    /**
     * @param leaf target leaf
     * @return a merkle proof for the target leaf, or null if it cannot be found in the tree
     */
    public fun merkleProof(leaf: Leaf): ByteArray? = merkleProof(this, leaf)

    public companion object {
        /**
         * @param tree script tree
         * @param leafHash target leaf hash
         * @return a merkle proof for the target leaf hash, or null if it cannot be found in the tree
         */
        @JvmStatic
        public fun merkleProof(tree: ScriptTree, leafHash: ByteVector32): ByteArray? {

            fun loop(t: ScriptTree, p: ByteArray): ByteArray? = when (t) {
                is Leaf -> if (t.hash() == leafHash) p else null
                is Branch -> loop(t.left, t.right.hash().toByteArray() + p) ?: loop(t.right, t.left.hash().toByteArray() + p)
            }

            return loop(tree, ByteArray(0))
        }

        @JvmStatic
        public fun merkleProof(tree: ScriptTree, leaf: Leaf): ByteArray? = merkleProof(tree, leaf.hash())
    }
}
