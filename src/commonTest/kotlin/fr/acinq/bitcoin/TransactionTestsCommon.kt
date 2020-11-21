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
import kotlin.test.assertEquals

class TransactionTestsCommon {
    @Test
    fun `read and write transactions`() {
        val hex =
            "0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000"
        val tx = Transaction.read(hex)
        assertEquals(hex, Hex.encode(Transaction.write(tx)))
    }

    @Test
    fun `decode transactions`() {
        // data copied from https://people.xiph.org/~greg/signdemo.txt
        val tx = Transaction.read("01000000010c432f4fb3e871a8bda638350b3d5c698cf431db8d6031b53e3fb5159e59d4a90000000000ffffffff0100f2052a010000001976a9143744841e13b90b4aca16fe793a7f88da3a23cc7188ac00000000")
        val script = Script.parse(tx.txOut[0].publicKeyScript)
        val publicKeyHash = when {
            script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] is OP_PUSHDATA && script[3] == OP_EQUALVERIFY && script[4] == OP_CHECKSIG -> (script[2] as OP_PUSHDATA).data
            else -> {
                throw RuntimeException("unexpected script $script")
            }
        }
        assertEquals("mkZBYBiq6DNoQEKakpMJegyDbw2YiNQnHT", Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, publicKeyHash))
    }

    @Test
    fun `create and verify simple transactions`() {
        val address = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
        val (prefix, pubkeyHash) = Base58Check.decode(address)
        assertEquals(prefix, Base58.Prefix.PubkeyAddressTestnet)
        val amount = 1000L.toSatoshi()

        val privateKey = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet).first
        val publicKey = privateKey.publicKey()

        val previousTx =
            Transaction.read("0100000001b021a77dcaad3a2da6f1611d2403e1298a902af8567c25d6e65073f6b52ef12d000000006a473044022056156e9f0ad7506621bc1eb963f5133d06d7259e27b13fcb2803f39c7787a81c022056325330585e4be39bcf63af8090a2deff265bc29a3fb9b4bf7a31426d9798150121022dfb538041f111bb16402aa83bd6a3771fa8aa0e5e9b0b549674857fafaf4fe0ffffffff0210270000000000001976a91415c23e7f4f919e9ff554ec585cb2a67df952397488ac3c9d1000000000001976a9148982824e057ccc8d4591982df71aa9220236a63888ac00000000")

        // create a transaction where the sig script is the pubkey script of the tx we want to redeem
        // the pubkey script is just a wrapper around the pub key hash
        // what it means is that we will sign a block of data that contains txid + from + to + amount

        // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
        val tx1 = Transaction(
            version = 1L,
            txIn = listOf(
                TxIn(OutPoint(previousTx.hash, 0), signatureScript = listOf(), sequence = 0xFFFFFFFFL)
            ),
            txOut = listOf(
                TxOut(amount = amount, publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(pubkeyHash), OP_EQUALVERIFY, OP_CHECKSIG))
            ),
            lockTime = 0L
        )

        // step #2: sign the tx
        val sig = Transaction.signInput(tx1, 0, previousTx.txOut[0].publicKeyScript, SigHash.SIGHASH_ALL, privateKey)
        val tx2 = tx1.updateSigScript(0, listOf(OP_PUSHDATA(sig), OP_PUSHDATA(publicKey)))

        // redeem the tx
        Transaction.correctlySpends(tx2, listOf(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `create and sign p2sh transactions`() {

        val key1 =
            PrivateKey(Hex.decode("C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA01"))
        val pub1 = key1.publicKey()
        val key2 =
            PrivateKey(Hex.decode("5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C01"))
        val pub2 = key2.publicKey()
        val key3 =
            PrivateKey(Hex.decode("29322B8277C344606BA1830D223D5ED09B9E1385ED26BE4AD14075F054283D8C01"))
        val pub3 = key3.publicKey()

        // we want to spend the first output of this tx
        val previousTx =
            Transaction.read("01000000014100d6a4d20ff14dfffd772aa3610881d66332ed160fc1094a338490513b0cf800000000fc0047304402201182201b586c6bfe6fd0346382900834149674d3cbb4081c304965440b1c0af20220023b62a997f4385e9279dc1078590556c6c6a85c3ec20fda407e95eb270e4de90147304402200c75f91f8bd741a8e71d11ff6a3e931838e32ceead34ccccfe3f73f01a81e45f02201795881473644b5f5ee6a8d8a90fe16e60eacace40e88900c375af2e0c51e26d014c69522103bd95bfc136869e2e5e3b0491e45c32634b0201a03903e210b01be248e04df8702103e04f714a4010ca5bb1423ef97012cb1008fb0dfd2f02acbcd3650771c46e4a8f2102913bd21425454688bdc2df2f0e518c5f3109b1c1be56e6e783a41c394c95dc0953aeffffffff0140420f00000000001976a914298e5c1e2d2cf22deffd2885394376c7712f9c6088ac00000000")
        val privateKey = PrivateKey.fromBase58("92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM", Base58.Prefix.SecretKeyTestnet).first
        val publicKey = privateKey.publicKey()

        // create and serialize a "2 out of 3" multisig script
        val redeemScript = Script.write(Script.createMultiSigMofN(2, listOf(pub1, pub2, pub3)))

        // the multisig adress is just that hash of this script
        val multisigAddress = Crypto.hash160(redeemScript)

        // we want to send money to our multisig adress by redeeming the first output
        // of 41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea
        // using our private key 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM

        // create a tx with empty input signature scripts
        val tx = Transaction(
            version = 1L,
            txIn = listOf(
                TxIn(OutPoint(previousTx.hash, 0), signatureScript = listOf(), sequence = 0xFFFFFFFFL)
            ),
            txOut = listOf(
                TxOut(
                    amount = 900000L.toSatoshi(), // 0.009 BTC in satoshi, meaning the fee will be 0.01-0.009 = 0.001
                    publicKeyScript = listOf(OP_HASH160, OP_PUSHDATA(multisigAddress), OP_EQUAL)
                )
            ),
            lockTime = 0L
        )

        // and sign it
        val sig = Transaction.signInput(tx, 0, previousTx.txOut[0].publicKeyScript, SigHash.SIGHASH_ALL, privateKey)
        val signedTx = tx.updateSigScript(0, listOf(OP_PUSHDATA(sig), OP_PUSHDATA(privateKey.publicKey().toUncompressedBin())))
        Transaction.correctlySpends(signedTx, listOf(previousTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // how to spend our tx ? let's try to sent its output to our public key
        val spendingTx = Transaction(
            version = 1L,
            txIn = listOf(
                TxIn(OutPoint(signedTx.hash, 0), signatureScript = listOf(), sequence = 0xFFFFFFFFL)
            ),
            txOut = listOf(
                TxOut(
                    amount = 900000L.toSatoshi(),
                    publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(publicKey.hash160()), OP_EQUALVERIFY, OP_CHECKSIG)
                )
            ),
            lockTime = 0L
        )

        // we need at least 2 signatures
        val sig1 = Transaction.signInput(spendingTx, 0, redeemScript, SigHash.SIGHASH_ALL, key1)
        val sig2 = Transaction.signInput(spendingTx, 0, redeemScript, SigHash.SIGHASH_ALL, key2)

        // update our tx with the correct sig script
        val sigScript = listOf(OP_0, OP_PUSHDATA(sig1), OP_PUSHDATA(sig2), OP_PUSHDATA(redeemScript))
        val signedSpendingTx = spendingTx.updateSigScript(0, sigScript)
        Transaction.correctlySpends(signedSpendingTx, listOf(signedTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
}
