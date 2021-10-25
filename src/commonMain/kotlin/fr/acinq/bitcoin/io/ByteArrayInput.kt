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

package fr.acinq.bitcoin.io

public class ByteArrayInput(private val array: ByteArray) : Input {

    private var position: Int = 0
    override val availableBytes: Int get() = array.size - position

    override fun read(): Int {
        return if (position < array.size) array[position++].toInt() and 0xFF else -1
    }

    override fun read(b: ByteArray, offset: Int, length: Int): Int {
        if (offset < 0 || offset > b.size || length < 0 || length > b.size - offset) throw IndexOutOfBoundsException()
        if (this.position >= array.size) return -1
        if (length == 0) return 0

        val copied = if (array.size - position < length) array.size - position else length
        array.copyInto(destination = b, destinationOffset = offset, startIndex = position, endIndex = position + copied)
        position += copied

        return copied
    }
}
