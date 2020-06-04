package fr.acinq.bitcoin

data class Satoshi(val sat: Long) : Comparable<Satoshi> {
    // @formatter:off
    operator fun plus(other: Satoshi) = Satoshi(sat + other.sat)
    operator fun minus(other: Satoshi) = Satoshi(sat - other.sat)
    operator fun times(m: Long) = Satoshi(sat * m)
    operator fun times(m: Double) = Satoshi((sat * m).toLong())
    operator fun div(d: Long) = Satoshi(sat / d)
    operator fun unaryMinus() = Satoshi(-sat)

    override fun compareTo(other: Satoshi): Int = sat.compareTo(other.sat)

    // We provide asymmetric min/max functions to provide more control on the return type.
    fun max(other: Satoshi): Satoshi = if (this > other) this else other
    fun min(other: Satoshi): Satoshi = if (this < other) this else other

    fun toLong(): Long = sat
    override fun toString() = "$sat sat"
    // @formatter:on
}

fun Long.toSatoshi() = Satoshi(this)