package fr.acinq.bitcoin

public data class Satoshi(val sat: Long) : Comparable<Satoshi> {
    // @formatter:off
    public operator fun plus(other: Satoshi): Satoshi = Satoshi(sat + other.sat)
    public operator fun minus(other: Satoshi): Satoshi = Satoshi(sat - other.sat)
    public operator fun times(m: Long): Satoshi = Satoshi(sat * m)
    public operator fun times(m: Double): Satoshi = Satoshi((sat * m).toLong())
    public operator fun div(d: Long): Satoshi = Satoshi(sat / d)
    public operator fun unaryMinus(): Satoshi = Satoshi(-sat)

    override fun compareTo(other: Satoshi): Int = sat.compareTo(other.sat)

    // We provide asymmetric min/max functions to provide more control on the return type.
    public fun max(other: Satoshi): Satoshi = if (this > other) this else other
    public fun min(other: Satoshi): Satoshi = if (this < other) this else other

    public fun toLong(): Long = sat
    override fun toString(): String = "$sat sat"
    // @formatter:on
}

public fun Long.toSatoshi(): Satoshi = Satoshi(this)
