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

package fr.acinq.bitcoin.crypto

import kotlin.experimental.xor

public fun Digest.hmac(key: ByteArray, data: ByteArray, blockSize: Int): ByteArray {
    val key1 = if (key.size > blockSize) hash(key) else key
    val key2 = if (key1.size < blockSize) key1 + ByteArray(blockSize - key1.size) else key1

    fun xor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size)
        val output = ByteArray(a.size)
        for (i in a.indices) output[i] = a[i] xor b[i]
        return output
    }

    val opad = xor(key2, ByteArray(blockSize) { 0x5c.toByte() })
    val ipad = xor(key2, ByteArray(blockSize) { 0x36.toByte() })
    return hash(opad + hash(ipad + data))
}
