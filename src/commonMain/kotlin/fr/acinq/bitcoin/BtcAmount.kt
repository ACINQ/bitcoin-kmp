package fr.acinq.bitcoin

sealed class BtcAmount

data class Satoshi(val amount: Long) : BtcAmount() {
    // @formatter:off
    fun toLong() = amount
    operator fun plus(other: Satoshi) = Satoshi(amount + other.amount)
    operator fun minus(other: Satoshi) = Satoshi(amount - other.amount)
    operator fun times(m: Long) = Satoshi(amount * m)
    operator fun div(d: Long) = Satoshi(amount / d)
    operator fun compareTo(other: Satoshi): Int =
        if (amount == other.toLong()) 0 else if (amount < other.amount) -1 else 1
    // @formatter:on
}
