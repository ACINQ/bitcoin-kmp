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

/**
 * leaf of a script tree used to create and spend tapscript transactions
 * @param id leaf id
 * @param script serialized bitcoin script
 * @param leafVersion tapscript version
 */
public data class ScriptLeaf(val id: Int, val script: ByteVector, val leafVersion: Int) {
    /**
     * tapleaf hash of this leaf
     */
    val hash: ByteVector32 = run {
        val buffer = ByteArrayOutput()
        buffer.write(leafVersion)
        BtcSerializer.writeScript(script, buffer)
        Crypto.taggedHash(buffer.toByteArray(), "TapLeaf")
    }
}

/**
 * Simple binary tree structure
 */
public sealed class ScriptTree<T> {
    public data class Leaf<T>(val value: T) : ScriptTree<T>()
    public data class Branch<T>(val left: ScriptTree<T>, val right: ScriptTree<T>) : ScriptTree<T>()

    public companion object {
        /**
         * @return the hash of the input merkle tree
         */
        public fun hash(tree: ScriptTree<ScriptLeaf>): ByteVector32 = when (tree) {
            is Leaf -> tree.value.hash
            is Branch -> {
                val h1 = hash(tree.left)
                val h2 = hash(tree.right)
                Crypto.taggedHash((if (LexicographicalOrdering.isLessThan(h1, h2)) h1 + h2 else h2 + h1).toByteArray(), "TapBranch")
            }
        }
    }
}
