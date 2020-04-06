package fr.acinq.bitcoin

import kotlinx.serialization.InternalSerializationApi
import kotlin.jvm.JvmStatic

/**
 * Lexicographical Ordering of Transaction Inputs and Outputs
 * see https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
 */
@InternalSerializationApi
@ExperimentalStdlibApi
object LexicographicalOrdering {
    tailrec fun isLessThanInternal(a: ByteArray, b: ByteArray): Boolean {
        return if (a.isEmpty() && b.isEmpty()) false
        else if (a.isEmpty()) true
        else if (b.isEmpty()) false
        else if (a.first() == b.first()) isLessThanInternal(a.drop(1).toByteArray(), b.drop(1).toByteArray())
        else (a.first().toInt() and 0xff) < (b.first().toInt() and 0xff)
    }

    @JvmStatic
    fun isLessThan(a: ByteArray, b: ByteArray): Boolean = isLessThanInternal(a, b)

    @JvmStatic
    fun isLessThan(a: ByteVector, b: ByteVector): Boolean = isLessThan(a.toByteArray(), b.toByteArray())

    @JvmStatic
    fun isLessThan(a: ByteVector32, b: ByteVector32): Boolean = isLessThan(a.toByteArray(), b.toByteArray())

    @JvmStatic
    fun isLessThan(a: OutPoint, b: OutPoint): Boolean {
        return if (a.txid == b.txid) a.index < b.index else isLessThan(a.txid, b.txid)
    }

    @JvmStatic
    fun compare(a: OutPoint, b: OutPoint): Int = if (a == b) 0 else if (isLessThan(a, b)) -1 else 1

    @JvmStatic
    fun isLessThan(a: TxIn, b: TxIn): Boolean = isLessThan(a.outPoint, b.outPoint)

    @JvmStatic
    fun compare(a: TxIn, b: TxIn): Int = if (a == b) 0 else if (isLessThan(a, b)) -1 else 1

    @JvmStatic
    fun isLessThan(a: TxOut, b: TxOut): Boolean {
        return if (a.amount == b.amount) isLessThan(a.publicKeyScript, b.publicKeyScript) else (a.amount < b.amount)
    }

    @JvmStatic
    fun compare(a: TxOut, b: TxOut): Int = if (a == b) 0 else if (isLessThan(a, b)) -1 else 1

    @JvmStatic
    fun isLessThan(a: PublicKey, b: PublicKey): Boolean = isLessThan(a.value, b.value)
    /**
     *
     * @param tx input transaction
     * @return the input tx with inputs and outputs sorted in lexicographical order
     */
    @JvmStatic
    fun sort(tx: Transaction): Transaction = tx.copy(
        txIn = tx.txIn.sortedWith(Comparator { a, b -> compare(a, b) }),
        txOut = tx.txOut.sortedWith(Comparator { a, b -> compare(a, b) })
    )
}