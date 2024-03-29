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
import kotlin.test.Test
import kotlin.test.assertFails

class CheckLockTimeVerifyTestsCommon {
    @Test
    fun `BIP65 payment channels`() {
        val previousTx = Transaction.read("0100000001bb4f5a244b29dc733c56f80c0fed7dd395367d9d3b416c01767c5123ef124f82000000006b4830450221009e6ed264343e43dfee2373b925915f7a4468e0bc68216606e40064561e6c097a022030f2a50546a908579d0fab539d5726a1f83cfd48d29b89ab078d649a8e2131a0012103c80b6c289bf0421d010485cec5f02636d18fb4ed0f33bfa6412e20918ebd7a34ffffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388acf0b0b805000000001976a914807c74c89592e8a260f04b5a3bc63e7bef8c282588ac00000000")
        val key = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet).first

        val keyAlice = PrivateKey.fromHex("C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA")
        val pubAlice = keyAlice.publicKey()

        val keyBob = PrivateKey.fromHex("5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C")
        val pubBob = keyBob.publicKey()

        // create a pub key script that can be redeemed either:
        // by Alice alone, in a tx which locktime is > 100
        // or by Alice and Bob, anytime
        // @formatter:off
        val scriptPubKey = listOf(
            OP_IF,
                OP_PUSHDATA(Hex.decode("64")), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_PUSHDATA(pubAlice), OP_CHECKSIG,
            OP_ELSE,
                OP_2, OP_PUSHDATA(pubAlice), OP_PUSHDATA(pubBob), OP_2, OP_CHECKMULTISIG,
            OP_ENDIF
        )
        // @formatter:on

        // create a tx that sends money to scriptPubKey
        val tx = run {
            val tmpTx = Transaction(
                version = 1L,
                txIn = listOf(TxIn(OutPoint(previousTx.hash, 0), sequence = 0L)),
                txOut = listOf(TxOut(amount = 100L.toSatoshi(), publicKeyScript = scriptPubKey)),
                lockTime = 100L
            )
            val sig = Transaction.signInput(tmpTx, 0, previousTx.txOut[0].publicKeyScript, SigHash.SIGHASH_ALL, previousTx.txOut[0].amount, SigVersion.SIGVERSION_BASE, key)
            tmpTx.updateSigScript(0, listOf(OP_PUSHDATA(sig), OP_PUSHDATA(key.publicKey())))
        }

        Transaction.correctlySpends(tx, listOf(previousTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // now we try to redeem this tx
        val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"

        // we can redeem this tx with a single signature from Alice, if the lock time of the redeeming tx is >= 100
        val tx1 = run {
            val tmpTx = Transaction(
                version = 1L,
                txIn = listOf(TxIn(OutPoint(tx.hash, 0), sequence = 0L)),
                txOut = listOf(TxOut(amount = 100L.toSatoshi(), publicKeyScript = Script.pay2pkh(Base58Check.decode(to).second))),
                lockTime = 100L
            )

            val sig = Transaction.signInput(tmpTx, 0, Script.write(scriptPubKey), SigHash.SIGHASH_ALL, keyAlice)

            // our script sig is simple our signature followed by "true"
            tmpTx.updateSigScript(0, listOf(OP_PUSHDATA(sig), OP_1))
        }
        Transaction.correctlySpends(tx1, listOf(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS or ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)

        // but we cannot redeem this tx with a single signature from Alice if the lock time of the redeeming tx is < 100
        val tx3 = run {
            val tmpTx = Transaction(
                version = 1L,
                txIn = listOf(TxIn(OutPoint(tx.hash, 0), sequence = 0L)),
                txOut = listOf(TxOut(100L.toSatoshi(), publicKeyScript = Script.pay2pkh(Base58Check.decode(to).second))),
                lockTime = 99L
            )

            val sig = Transaction.signInput(tmpTx, 0, Script.write(scriptPubKey), SigHash.SIGHASH_ALL, keyAlice)

            // our script sig is simple our signature followed by "true"
            tmpTx.updateSigScript(0, listOf(OP_PUSHDATA(sig), OP_1))
        }

        assertFails {
            Transaction.correctlySpends(tx3, listOf(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS or ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
        }

        // we can also redeem this tx with 2 signatures from Alice and Bob
        val tx2 = run {
            val tmpTx = Transaction(
                version = 1L,
                txIn = listOf(TxIn(OutPoint(tx.hash, 0), sequence = 0L)),
                txOut = listOf(TxOut(100L.toSatoshi(), publicKeyScript = Script.pay2pkh(Base58Check.decode(to).second))),
                lockTime = 0L
            )

            val sig1 = Transaction.signInput(tmpTx, 0, scriptPubKey, SigHash.SIGHASH_ALL, keyAlice)
            val sig2 = Transaction.signInput(tmpTx, 0, scriptPubKey, SigHash.SIGHASH_ALL, keyBob)
            val sigScript = listOf(OP_0, OP_PUSHDATA(sig1), OP_PUSHDATA(sig2), OP_0)

            tmpTx.updateSigScript(0, sigScript)
        }
        Transaction.correctlySpends(tx2, listOf(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS or ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
    }
}