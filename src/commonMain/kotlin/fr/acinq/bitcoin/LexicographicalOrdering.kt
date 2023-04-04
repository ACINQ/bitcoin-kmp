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

import kotlin.jvm.JvmStatic

/**
 * Lexicographical Ordering of Transaction Inputs and Outputs.
 * See https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
 */
public object LexicographicalOrdering {
    private tailrec fun isLessThanInternal(a: ByteArray, b: ByteArray): Boolean {
        return when {
            a.isEmpty() && b.isEmpty() -> false
            a.isEmpty() -> true
            b.isEmpty() -> false
            a.first() == b.first() -> isLessThanInternal(a.drop(1).toByteArray(), b.drop(1).toByteArray())
            else -> (a.first().toInt() and 0xff) < (b.first().toInt() and 0xff)
        }
    }

    @JvmStatic
    public fun isLessThan(a: ByteArray, b: ByteArray): Boolean = isLessThanInternal(a, b)

    @JvmStatic
    public fun isLessThan(a: ByteVector, b: ByteVector): Boolean = isLessThan(a.toByteArray(), b.toByteArray())

    @JvmStatic
    public fun isLessThan(a: ByteVector32, b: ByteVector32): Boolean = isLessThan(a.toByteArray(), b.toByteArray())

    @JvmStatic
    public fun isLessThan(a: OutPoint, b: OutPoint): Boolean {
        return if (a.txid == b.txid) a.index < b.index else isLessThan(a.txid.value, b.txid.value)
    }

    @JvmStatic
    public fun compare(a: OutPoint, b: OutPoint): Int = if (a == b) 0 else if (isLessThan(a, b)) -1 else 1

    @JvmStatic
    public fun isLessThan(a: TxIn, b: TxIn): Boolean = isLessThan(a.outPoint, b.outPoint)

    @JvmStatic
    public fun compare(a: TxIn, b: TxIn): Int = if (a == b) 0 else if (isLessThan(a, b)) -1 else 1

    @JvmStatic
    public fun isLessThan(a: TxOut, b: TxOut): Boolean {
        return if (a.amount == b.amount) isLessThan(a.publicKeyScript, b.publicKeyScript) else (a.amount < b.amount)
    }

    @JvmStatic
    public fun compare(a: TxOut, b: TxOut): Int = if (a == b) 0 else if (isLessThan(a, b)) -1 else 1

    @JvmStatic
    public fun isLessThan(a: PublicKey, b: PublicKey): Boolean = isLessThan(a.value, b.value)

    @JvmStatic
    public fun compare(a: PublicKey, b: PublicKey): Int = if (a == b) 0 else if (isLessThan(a, b)) -1 else 1

    /**
     * @param tx input transaction
     * @return the input tx with inputs and outputs sorted in lexicographical order
     */
    @JvmStatic
    public fun sort(tx: Transaction): Transaction = tx.copy(
        txIn = tx.txIn.sortedWith { a, b -> compare(a, b) },
        txOut = tx.txOut.sortedWith { a, b -> compare(a, b) }
    )
}