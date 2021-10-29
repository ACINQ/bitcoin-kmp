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

public interface Input {
    public val availableBytes: Int
    public fun read(): Int
    public fun read(b: ByteArray, offset: Int = 0, length: Int = b.size - offset): Int
}

/** Read bytes from the input. Return null if the input is too small. */
public fun Input.readNBytes(n: Int): ByteArray? = if (availableBytes < n) null else ByteArray(n).also { read(it, 0, n) }
