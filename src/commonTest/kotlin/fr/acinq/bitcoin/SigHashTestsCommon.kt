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

import fr.acinq.bitcoin.SigHash.SIGHASH_ALL
import fr.acinq.bitcoin.SigHash.SIGHASH_ANYONECANPAY
import kotlin.test.Test
import kotlin.test.assertFails

class SighashSpec {

    @Test
    fun `SIGHASH_ANYONECANPAY lets you add inputs`() {
        val privateKeys = listOf(
            PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet).first,
            PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet).first
        )

        val publicKeys = privateKeys.map { it.publicKey() }

        val previousTx = listOf(
            Transaction(version = 2, txIn = listOf(), txOut = listOf(TxOut(4_200_000.sat(), Script.pay2pkh(publicKeys[0]))), lockTime = 0),
            Transaction(version = 2, txIn = listOf(), txOut = listOf(TxOut(4_200_000.sat(), Script.pay2pkh(publicKeys[1]))), lockTime = 0)
        )

        // create a tx with no inputs
        val tx = Transaction(version = 2, txIn = listOf(), txOut = listOf(TxOut(8_000_000.sat(), Script.pay2wsh(Script.createMultiSigMofN(2, publicKeys)))), lockTime = 0L)

        // add an input
        val tx1 = run {
            val tmp = tx.addInput(TxIn(OutPoint(previousTx[0], 0), sequence = 0xFFFFFFFFL))
            val sig = Transaction.signInput(tmp, 0, Script.pay2pkh(publicKeys[0]), SIGHASH_ALL or SIGHASH_ANYONECANPAY, previousTx[0].txOut[0].amount, SigVersion.SIGVERSION_BASE, privateKeys[0])
            tmp.updateSigScript(0, listOf(OP_PUSHDATA(sig), OP_PUSHDATA(publicKeys[0])))
        }

        Transaction.correctlySpends(tx1, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // add another input: the first input's sig si still valid !
        val tx2 = run {
            val tmp = tx1.addInput(TxIn(OutPoint(previousTx[1], 0), sequence = 0xFFFFFFFFL))
            val sig = Transaction.signInput(tmp, 1, Script.pay2pkh(publicKeys[1]), SIGHASH_ALL or SIGHASH_ANYONECANPAY, previousTx[1].txOut[0].amount, SigVersion.SIGVERSION_BASE, privateKeys[1])
            tmp.updateSigScript(1, listOf(OP_PUSHDATA(sig), OP_PUSHDATA(publicKeys[1])))
        }

        Transaction.correctlySpends(tx2, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // but I cannot change the tx output
        val tx3 = tx2.copy(txOut = tx2.txOut.updated(0, tx2.txOut[0].copy(amount = 4_000_000.sat())))

        assertFails {
            Transaction.correctlySpends(tx3, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
    }

    @Test
    fun `SIGHASH_ANYONECANPAY lets you add inputs -- SEGWIT version`() {
        val privateKeys = listOf(
            PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet).first,
            PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet).first
        )

        val publicKeys = privateKeys.map { it.publicKey() }

        val previousTx = listOf(
            Transaction(version = 2, txIn = listOf(), txOut = listOf(TxOut(4_200_000.sat(), Script.pay2wpkh(publicKeys[0]))), lockTime = 0),
            Transaction(version = 2, txIn = listOf(), txOut = listOf(TxOut(4_200_000.sat(), Script.pay2wpkh(publicKeys[1]))), lockTime = 0)
        )

        // create a tx with no inputs
        val tx = Transaction(version = 2, txIn = listOf(), txOut = listOf(TxOut(8_000_000.sat(), Script.pay2wsh(Script.createMultiSigMofN(2, publicKeys)))), lockTime = 0L)

        // add an input
        val tx1 = run {
            val tmp = tx.addInput(TxIn(OutPoint(previousTx[0], 0), sequence = 0xFFFFFFFFL))
            val sig = Transaction.signInput(tmp, 0, Script.pay2pkh(publicKeys[0]), SIGHASH_ALL or SIGHASH_ANYONECANPAY, previousTx[0].txOut[0].amount, SigVersion.SIGVERSION_WITNESS_V0, privateKeys[0])
            tmp.updateWitness(0, ScriptWitness(listOf(sig.byteVector(), publicKeys[0].value)))
        }

        Transaction.correctlySpends(tx1, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // add another input: the first input's sig si still valid !
        val tx2 = run {
            val tmp = tx1.addInput(TxIn(OutPoint(previousTx[1], 0), sequence = 0xFFFFFFFFL))
            val sig = Transaction.signInput(tmp, 1, Script.pay2pkh(publicKeys[1]), SIGHASH_ALL or SIGHASH_ANYONECANPAY, previousTx[1].txOut[0].amount, SigVersion.SIGVERSION_WITNESS_V0, privateKeys[1])
            tmp.updateWitness(1, ScriptWitness(listOf(sig.byteVector(), publicKeys[1].value)))
        }

        Transaction.correctlySpends(tx2, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // but I cannot change the tx output
        val tx3 = tx2.copy(txOut = tx2.txOut.updated(0, tx2.txOut[0].copy(amount = 4_000_000.sat())))
        assertFails {
            Transaction.correctlySpends(tx3, previousTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
    }

}