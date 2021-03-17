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

import kotlin.jvm.JvmStatic

public interface Digest {
    /**
     * return the algorithm name
     *
     * @return the algorithm name
     */
    public fun getAlgorithmName(): String

    /**
     * return the size, in bytes, of the digest produced by this message digest.
     *
     * @return the size, in bytes, of the digest produced by this message digest.
     */
    public fun getDigestSize(): Int

    /**
     * update the message digest with a single byte.
     *
     * @param `in` the input byte to be entered.
     */
    public fun update(input: Byte)

    /**
     * update the message digest with a block of bytes.
     *
     * @param `in` the byte array containing the data.
     * @param inputOffset the offset into the byte array where the data starts.
     * @param len the length of the data.
     */
    public fun update(input: ByteArray, inputOffset: Int, len: Int)

    /**
     * close the digest, producing the final digest value. The doFinal
     * call leaves the digest reset.
     *
     * @param out the array the digest is to be copied into.
     * @param outOffset the offset into the out array the digest is to start at.
     */
    public fun doFinal(out: ByteArray, outOffset: Int): Int

    /**
     * reset the digest back to it's initial state.
     */
    public fun reset()

    public fun hash(input: ByteArray, inputOffset: Int, len: Int): ByteArray {
        reset()
        update(input, inputOffset, len)
        val output = ByteArray(getDigestSize())
        doFinal(output, 0)
        return output
    }

    public fun hash(input: ByteArray): ByteArray = hash(input, 0, input.size)

    public companion object {
        @JvmStatic public fun sha1(): Digest = Sha1()
        @JvmStatic public fun sha256(): Digest = Sha256()
        @JvmStatic public fun sha512(): Digest = Sha512()
        @JvmStatic public fun ripemd160(): Digest = Ripemd160()
    }
}

internal expect fun Sha1(): Digest
internal expect fun Sha256(): Digest
internal expect fun Sha512(): Digest
