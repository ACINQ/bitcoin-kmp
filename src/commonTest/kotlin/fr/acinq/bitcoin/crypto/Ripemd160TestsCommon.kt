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

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertTrue

class Ripemd160TestsCommon {
    @Test // from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
    fun `reference tests`() {
        assertTrue { Digest.ripemd160().hash("".encodeToByteArray()).contentEquals(Hex.decode("9c1185a5c5e9fc54612808977ee8f548b2258d31")) }
        assertTrue { Digest.ripemd160().hash("abc".encodeToByteArray()).contentEquals(Hex.decode("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")) }
        assertTrue { Digest.ripemd160().hash("message digest".encodeToByteArray()).contentEquals(Hex.decode("5d0689ef49d2fae572b881b123a85ffa21595f36")) }
        assertTrue { Digest.ripemd160().hash("abcdefghijklmnopqrstuvwxyz".encodeToByteArray()).contentEquals(Hex.decode("f71c27109c692c1b56bbdceb5b9d2865b3708dbc")) }
        assertTrue { Digest.ripemd160().hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".encodeToByteArray()).contentEquals(Hex.decode("12a053384a9c0c88e405a06c27dcf49ada62eb2b")) }
        assertTrue { Digest.ripemd160().hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".encodeToByteArray()).contentEquals(Hex.decode("e0b62c9952c259e438bbbf82f643203f94e57550")) }
        assertTrue { Digest.ripemd160().hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".encodeToByteArray()).contentEquals(Hex.decode("b0e20b6e3116640286ed3a87a5713079b21f5189")) }
        assertTrue { Digest.ripemd160().hash(Array(8) { "1234567890" }.reduce { acc, s -> acc + s }.encodeToByteArray()).contentEquals(Hex.decode("9b752e45573d4b39f4dbd3323cab82bf63326bfb")) }
        assertTrue { Digest.ripemd160().hash(ByteArray(1000_000) { 0x61.toByte() }).contentEquals(Hex.decode("52783243c1697bdbe16d37f97f68f08325dc1528")) }
    }
}