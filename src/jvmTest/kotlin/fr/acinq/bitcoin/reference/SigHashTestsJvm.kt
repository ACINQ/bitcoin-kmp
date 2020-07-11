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

package fr.acinq.bitcoin.reference

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import fr.acinq.bitcoin.Transaction
import fr.acinq.secp256k1.Hex
import org.junit.Test

class SigHashTestsJvm {
    val mapper = jacksonObjectMapper()

    @Test
    fun `reference client sighash test`() {
        val stream = javaClass.getResourceAsStream("/data/sighash.json")
        // 	["raw_transaction, script, input_index, hashType, signature_hash (result)"],

        val tests = mapper.readValue<Array<Array<JsonNode>>>(stream)
        tests.filter { it -> it.size == 5 }.forEach { it ->
            val raw_transaction = it[0].textValue()
            val script = it[1].textValue()
            val input_index = it[2].intValue()
            val hashType = it[3].intValue()
            val signature_hash = it[4].textValue()

            val tx = Transaction.read(raw_transaction)
            val hash = Transaction.hashForSigning(tx, input_index, Hex.decode(script), hashType)
            if (Hex.encode(hash.reversed().toByteArray()) != signature_hash) {
                println("sighash error")
                println("$raw_transaction")
                println("$script")
                println("$input_index")
                println("$hashType")
                println("$signature_hash")
                throw RuntimeException("sighash error")
            }
        }
    }
}