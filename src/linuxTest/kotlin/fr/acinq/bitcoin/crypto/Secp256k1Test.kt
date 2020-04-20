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

import fr.acinq.bitcoin.Hex
import kotlin.test.Test
import kotlin.test.assertEquals


internal class Secp256k1Test {

    @Test
    fun computePublicKey() {
        val priv = Hex.decode("0101010101010101010101010101010101010101010101010101010101010101")
        val pub = Secp256k1.computePublicKey(priv)
        assertEquals("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", Hex.encode(pub))
    }

    @Test
    fun parsePublicKey() {
        val pub = Hex.decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")
        val parsed = Secp256k1.parsePublicKey(pub)
        assertEquals("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1", Hex.encode(parsed))
    }

    @Test
    fun ecdh() {
    }

    @Test
    fun privateKeyAdd() {
        val priv = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530")
        val tweak = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3")
        val priv1 =  Secp256k1.privateKeyAdd(priv, tweak)
        assertEquals("A168571E189E6F9A7E2D657A4B53AE99B909F7E712D1C23CED28093CD57C88F3", Hex.encode(priv1).toUpperCase())
    }

    @Test
    fun privateKeyNegate() {
    }

    @Test
    fun privateKeyMul() {
    }

    @Test
    fun publicKeyAdd() {
        val pub1 = Hex.decode("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1")
        val pub2 = Hex.decode("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0")
        val combined = Secp256k1.publicKeyAdd(pub1, pub2)
        assertEquals("02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337", Hex.encode(combined))
    }

    @Test
    fun publicKeyNegate() {
    }

    @Test
    fun publicKeyMul() {
    }

    @Test
    fun sign() {
    }

    @Test
    fun verify() {
    }

    @Test
    fun compact2der() {
    }

    @Test
    fun der2compact() {
    }

    @Test
    fun signatureNormalize() {
    }

    @Test
    fun recoverPublicKey() {
    }
}