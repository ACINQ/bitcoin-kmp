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

public data class Satoshi(val sat: Long) : Comparable<Satoshi> {
    // @formatter:off
    public operator fun plus(other: Satoshi): Satoshi = Satoshi(sat + other.sat)
    public operator fun minus(other: Satoshi): Satoshi = Satoshi(sat - other.sat)
    public operator fun times(m: Int): Satoshi = Satoshi(sat * m)
    public operator fun times(m: Long): Satoshi = Satoshi(sat * m)
    public operator fun times(m: Double): Satoshi = Satoshi((sat * m).toLong())
    public operator fun div(d: Int): Satoshi = Satoshi(sat / d)
    public operator fun div(d: Long): Satoshi = Satoshi(sat / d)
    public operator fun unaryMinus(): Satoshi = Satoshi(-sat)

    override fun compareTo(other: Satoshi): Int = sat.compareTo(other.sat)

    public fun max(other: Satoshi): Satoshi = if (this > other) this else other
    public fun min(other: Satoshi): Satoshi = if (this < other) this else other

    public fun toLong(): Long = sat

    public fun toULong(): ULong = sat.toULong()
    override fun toString(): String = "$sat sat"
    // @formatter:on
}

public fun Long.sat(): Satoshi = Satoshi(this)
public fun Long.toSatoshi(): Satoshi = Satoshi(this)
public fun Int.sat(): Satoshi = Satoshi(this.toLong())
public fun Int.toSatoshi(): Satoshi = Satoshi(this.toLong())
