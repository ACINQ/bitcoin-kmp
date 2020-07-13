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
import org.junit.Test

class Pkbdf2TestsJvm {
    @Test
    fun `generate`() {
        val password =
            Hex.decode("6162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e2061626f7574")
        val salt = Hex.decode("6d6e656d6f6e6963")
        val foo = Pbkdf2.generate(salt, 2048, 64, Pbkdf2.Hmac512(password))
        println(Hex.encode(foo))
    }
}