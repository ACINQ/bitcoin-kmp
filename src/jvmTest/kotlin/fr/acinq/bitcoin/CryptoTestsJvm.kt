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

import fr.acinq.secp256k1.Hex
import org.junit.Test
import kotlin.test.assertEquals

@ExperimentalStdlibApi
class CryptoTestsJvm {

    @Test
    fun `recover public keys from signatures (secp256k1 test)`() {
        val stream = javaClass.getResourceAsStream("/recid.txt")
        val iterator = stream.bufferedReader(charset("UTF-8")).lines().iterator()
        var priv: PrivateKey? = null
        var message: ByteVector? = null
        var pub: PublicKey? = null
        //var sig: ByteVector? = null
        var recid: Int

        while (iterator.hasNext()) {
            val line = iterator.next()
            val values = line.split(" = ")
            val lhs = values[0]
            val rhs = values[1]
            when (lhs) {
                "privkey" -> priv = PrivateKey(ByteVector(rhs).toByteArray())
                "message" -> message = ByteVector(rhs)
                "pubkey" -> pub = PublicKey(ByteVector(rhs))
                //"sig" -> sig = ByteVector(rhs)
                "recid" -> {
                    recid = rhs.toInt()
                    assert(priv!!.publicKey() == pub)
                    val sig1 = Crypto.sign(message!!.toByteArray(), priv)
                    val pub1 = Crypto.recoverPublicKey(sig1, message.toByteArray(), recid)
                    assert(pub1 == pub)
                }
            }
        }
    }
}