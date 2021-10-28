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

import kotlin.math.absoluteValue

public data class MilliBtc(val mbtc: Double) : Comparable<MilliBtc> {
    init {
        require(mbtc.absoluteValue <= 21e9) { "amount must not be greater than 21 million BTC" }
    }

    // @formatter:off
    public operator fun plus(other: MilliBtc): MilliBtc = MilliBtc(mbtc + other.mbtc)
    public operator fun minus(other: MilliBtc): MilliBtc = MilliBtc(mbtc - other.mbtc)
    public operator fun times(m: Int): MilliBtc = MilliBtc(mbtc * m)
    public operator fun times(m: Long): MilliBtc = MilliBtc(mbtc * m)
    public operator fun times(m: Double): MilliBtc = MilliBtc(mbtc * m)
    public operator fun div(d: Int): MilliBtc = MilliBtc(mbtc / d)
    public operator fun div(d: Long): MilliBtc = MilliBtc(mbtc / d)
    public operator fun unaryMinus(): MilliBtc = MilliBtc(-mbtc)

    override fun compareTo(other: MilliBtc): Int = mbtc.compareTo(other.mbtc)

    public fun max(other: MilliBtc): MilliBtc = if (this > other) this else other
    public fun min(other: MilliBtc): MilliBtc = if (this < other) this else other

    public fun toDouble(): Double = mbtc
    public fun toLong(): Long = mbtc.toLong()
    public fun toSatoshi(): Satoshi = Satoshi((mbtc * 100_000).toLong())
    public fun toBtc(): Btc = Btc(mbtc / 1000)
    override fun toString(): String = "$mbtc mbtc"
    // @formatter:on
}

public fun Double.mbtc(): MilliBtc = MilliBtc(this)
public fun Int.mbtc(): MilliBtc = MilliBtc(this.toDouble())
public fun Long.mbtc(): MilliBtc = MilliBtc(this.toDouble())

public data class Btc(val btc: Double) : Comparable<Btc> {
    init {
        require(btc.absoluteValue <= 21e6) { "amount must not be greater than 21 million BTC" }
    }

    // @formatter:off
    public operator fun plus(other: Btc): Btc = Btc(btc + other.btc)
    public operator fun minus(other: Btc): Btc = Btc(btc - other.btc)
    public operator fun times(m: Int): Btc = Btc(btc * m)
    public operator fun times(m: Long): Btc = Btc(btc * m)
    public operator fun times(m: Double): Btc = Btc(btc * m)
    public operator fun div(d: Int): Btc = Btc(btc / d)
    public operator fun div(d: Long): Btc = Btc(btc / d)
    public operator fun unaryMinus(): Btc = Btc(-btc)

    override fun compareTo(other: Btc): Int = btc.compareTo(other.btc)

    public fun max(other: Btc): Btc = if (this > other) this else other
    public fun min(other: Btc): Btc = if (this < other) this else other

    public fun toDouble(): Double = btc
    public fun toLong(): Long = btc.toLong()
    public fun toMilliBtc(): MilliBtc = MilliBtc(btc * 1000)
    public fun toSatoshi(): Satoshi = Satoshi((btc * 100_000_000).toLong())
    override fun toString(): String = "$btc btc"
    // @formatter:on
}

public fun Double.btc(): Btc = Btc(this)
public fun Int.btc(): Btc = Btc(this.toDouble())
public fun Long.btc(): Btc = Btc(this.toDouble())
