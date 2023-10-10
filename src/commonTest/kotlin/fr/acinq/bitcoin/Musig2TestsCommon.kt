package fr.acinq.bitcoin

import fr.acinq.bitcoin.musig2.Musig2
import fr.acinq.bitcoin.musig2.PublicNonce
import fr.acinq.bitcoin.musig2.SecretNonce
import fr.acinq.bitcoin.musig2.SessionCtx
import fr.acinq.bitcoin.reference.TransactionTestsCommon
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class Musig2TestsCommon {
    @Test
    fun `sort public keys`() {
        val tests = TransactionTestsCommon.readData("musig2/key_sort_vectors.json")
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val expected = tests.jsonObject["sorted_pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        assertEquals(expected, Musig2.keySort(pubkeys))
    }

    @Test
    fun `aggregate public keys`() {
        val tests = TransactionTestsCommon.readData("musig2/key_agg_vectors.json")
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = XonlyPublicKey(ByteVector32.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content))
            val ctx = Musig2.keyAgg(keyIndices.map { pubkeys[it] })
            assertEquals(expected, ctx.Q.xOnly())
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertFails {
                var ctx = Musig2.keyAgg(keyIndices.map { pubkeys[it] })
                tweakIndices.zip(isXonly).forEach { ctx = ctx.tweak(tweaks[it.first], it.second) }
            }
        }
    }

    @Test
    fun `generate secret nonce`() {
        val tests = TransactionTestsCommon.readData("musig2/nonce_gen_vectors.json")
        tests.jsonObject["test_cases"]!!.jsonArray.forEach {
            val randprime = ByteVector32.fromValidHex(it.jsonObject["rand_"]!!.jsonPrimitive.content)
            val sk = it.jsonObject["sk"]?.jsonPrimitive?.contentOrNull?.let { PrivateKey.fromHex(it) }
            val pk = PublicKey.fromHex(it.jsonObject["pk"]!!.jsonPrimitive.content)
            val aggpk = it.jsonObject["aggpk"]?.jsonPrimitive?.contentOrNull?.let { XonlyPublicKey(ByteVector32.fromValidHex(it)) }
            val msg = it.jsonObject["msg"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) }
            val extraInput = it.jsonObject["extra_in"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) }
            val expectedSecnonce = SecretNonce.fromValidHex(it.jsonObject["expected_secnonce"]!!.jsonPrimitive.content)
            val expectedPubnonce = PublicNonce.fromValidHex(it.jsonObject["expected_pubnonce"]!!.jsonPrimitive.content)
            val secnonce = SecretNonce.generate(sk, pk, aggpk, msg, extraInput, randprime)
            assertEquals(expectedSecnonce, secnonce)
            assertEquals(expectedPubnonce, secnonce.publicNonce())
        }
    }

    @Test
    fun `aggregate nonces`() {
        val tests = TransactionTestsCommon.readData("musig2/nonce_agg_vectors.json")
        val nonces = tests.jsonObject["pnonces"]!!.jsonArray.map { PublicNonce.fromValidHex(it.jsonPrimitive.content) }
        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = PublicNonce.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val agg = PublicNonce.aggregate(nonceIndices.map { nonces[it] })
            assertEquals(expected, agg)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertFails {
                PublicNonce.aggregate(nonceIndices.map { nonces[it] })
            }
        }
    }

    @Test
    fun `sign`() {
        val tests = TransactionTestsCommon.readData("musig2/sign_verify_vectors.json")
        val sk = PrivateKey.fromHex(tests.jsonObject["sk"]!!.jsonPrimitive.content)
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val secnonces = tests.jsonObject["secnonces"]!!.jsonArray.map { SecretNonce.fromValidHex(it.jsonPrimitive.content) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { PublicNonce.fromValidHex(it.jsonPrimitive.content) }
        val aggnonces = tests.jsonObject["aggnonces"]!!.jsonArray.map { PublicNonce.fromValidHex(it.jsonPrimitive.content) }
        val msgs = tests.jsonObject["msgs"]!!.jsonArray.map { ByteVector(it.jsonPrimitive.content) }

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = ByteVector32.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val agg = PublicNonce.aggregate(nonceIndices.map { pnonces[it] })
            assertEquals(aggnonces[it.jsonObject["aggnonce_index"]!!.jsonPrimitive.int], agg)
            val ctx = SessionCtx(
                agg,
                keyIndices.map { pubkeys[it] },
                listOf(),
                msgs[it.jsonObject["msg_index"]!!.jsonPrimitive.int]
            )
            val psig = ctx.sign(secnonces[keyIndices[signerIndex]], sk)
            assertEquals(expected, psig)
            assertTrue {
                ctx.partialSigVerify(psig, pnonces[nonceIndices[signerIndex]], pubkeys[keyIndices[signerIndex]])
            }
        }

        tests.jsonObject["sign_error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertFails {
                val ctx = SessionCtx(
                    aggnonces[it.jsonObject["aggnonce_index"]!!.jsonPrimitive.int],
                    keyIndices.map { pubkeys[it] },
                    listOf(),
                    msgs[it.jsonObject["msg_index"]!!.jsonPrimitive.int]
                )
                ctx.sign(secnonces[it.jsonObject["secnonce_index"]!!.jsonPrimitive.int], sk)
            }
        }
    }

    @Test
    fun `aggregate signatures`() {
        val tests = TransactionTestsCommon.readData("musig2/sig_agg_vectors.json")
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { PublicNonce.fromValidHex(it.jsonPrimitive.content) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
        val psigs = tests.jsonObject["psigs"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
        val msg = ByteVector.fromHex(tests.jsonObject["msg"]!!.jsonPrimitive.content)

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val psigIndices = it.jsonObject["psig_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = ByteVector64.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val aggnonce = PublicNonce.aggregate(nonceIndices.map { pnonces[it] })
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertEquals(PublicNonce.fromValidHex(it.jsonObject["aggnonce"]!!.jsonPrimitive.content), aggnonce)
            val ctx = SessionCtx(
                aggnonce,
                keyIndices.map { pubkeys[it] },
                tweakIndices.zip(isXonly).map { tweaks[it.first] to it.second },
                msg
            )
            val aggsig = ctx.partialSigAgg(psigIndices.map { psigs[it] })
            assertEquals(expected, aggsig)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val psigIndices = it.jsonObject["psig_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val aggnonce = PublicNonce.aggregate(nonceIndices.map { pnonces[it] })
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertEquals(PublicNonce.fromValidHex(it.jsonObject["aggnonce"]!!.jsonPrimitive.content), aggnonce)
            assertFails {
                val ctx = SessionCtx(
                    aggnonce,
                    keyIndices.map { pubkeys[it] },
                    tweakIndices.zip(isXonly).map { tweaks[it.first] to it.second },
                    msg
                )
                ctx.partialSigAgg(psigIndices.map { psigs[it] })
            }
        }
    }

    @Test
    fun `tweak tests`() {
        val tests = TransactionTestsCommon.readData("musig2/tweak_vectors.json")
        val sk = PrivateKey.fromHex(tests.jsonObject["sk"]!!.jsonPrimitive.content)
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { PublicNonce.fromValidHex(it.jsonPrimitive.content) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
        val msg = ByteVector.fromHex(tests.jsonObject["msg"]!!.jsonPrimitive.content)

        val secnonce = SecretNonce.fromValidHex(tests.jsonObject["secnonce"]!!.jsonPrimitive.content)
        val aggnonce = PublicNonce.fromValidHex(tests.jsonObject["aggnonce"]!!.jsonPrimitive.content)

        assertEquals(pubkeys[0], sk.publicKey())
        assertEquals(pnonces[0], secnonce.publicNonce())
        assertEquals(aggnonce, PublicNonce.aggregate(listOf(pnonces[0], pnonces[1], pnonces[2])))

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = ByteVector32.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content)
            assertEquals(aggnonce, PublicNonce.aggregate(nonceIndices.map { pnonces[it] }))
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val ctx = SessionCtx(
                aggnonce,
                keyIndices.map { pubkeys[it] },
                tweakIndices.zip(isXonly).map { tweaks[it.first] to it.second },
                msg
            )
            val psig = ctx.sign(secnonce, sk)
            assertEquals(expected, psig)
            assertTrue { ctx.partialSigVerify(psig, pnonces[nonceIndices[signerIndex]], pubkeys[keyIndices[signerIndex]]) }
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertEquals(aggnonce, PublicNonce.aggregate(nonceIndices.map { pnonces[it] }))
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            assertFails {
                val ctx = SessionCtx(
                    aggnonce,
                    keyIndices.map { pubkeys[it] },
                    tweakIndices.zip(isXonly).map { tweaks[it.first] to it.second },
                    msg
                )
                val psig = ctx.sign(secnonce, sk)
                ctx.partialSigVerify(psig, pnonces[nonceIndices[signerIndex]], pubkeys[keyIndices[signerIndex]])
            }
        }
    }

    @Test
    fun `simple musig2 example`() {
        val random = kotlin.random.Random.Default
        val msg = random.nextBytes(32).byteVector32()

        val privkeys = listOf(
            PrivateKey(ByteArray(32) { 1 }),
            PrivateKey(ByteArray(32) { 2 }),
            PrivateKey(ByteArray(32) { 3 }),
        )
        val pubkeys = privkeys.map { it.publicKey() }

        val plainTweak = ByteVector32("this could be a BIP32 tweak....".encodeToByteArray() + ByteArray(1))
        val xonlyTweak = ByteVector32("this could be a taproot tweak..".encodeToByteArray() + ByteArray(1))

        val aggsig = run {
            val secnonces = privkeys.map {
                SecretNonce.generate(it, it.publicKey(), null, null, null, random.nextBytes(32).byteVector32())
            }

            val pubnonces = secnonces.map { it.publicNonce() }

            // aggregate public nonces
            val aggnonce = PublicNonce.aggregate(pubnonces)

            // create a signing session
            val ctx = SessionCtx(
                aggnonce,
                pubkeys,
                listOf(Pair(plainTweak, false), Pair(xonlyTweak, true)),
                msg
            )

            // create partial signatures
            val psigs = privkeys.indices.map {
                ctx.sign(secnonces[it], privkeys[it])
            }

            // verify partial signatures
            pubkeys.indices.forEach {
                assertTrue(ctx.partialSigVerify(psigs[it], pubnonces[it], pubkeys[it]))
            }

            // aggregate partial signatures
            ctx.partialSigAgg(psigs)
        }

        // aggregate public keys
        val aggpub = Musig2.keyAgg(pubkeys)
            .tweak(plainTweak, false)
            .tweak(xonlyTweak, true)

        // check that the aggregated signature is a valid, plain Schnorr signature for the aggregated public key
        assertTrue(Crypto.verifySignatureSchnorr(msg, aggsig, aggpub.Q.xOnly()))
    }

    @Test
    fun `use musig2 to replace multisig 2-of-2`() {
        val alicePrivKey = PrivateKey(ByteArray(32) { 1 })
        val alicePubKey = alicePrivKey.publicKey()
        val bobPrivKey = PrivateKey(ByteArray(32) { 2 })
        val bobPubKey = bobPrivKey.publicKey()

        // Alice and Bob exchange public keys and agree on a common aggregated key
        val internalPubKey = Musig2.keyAgg(listOf(alicePubKey, bobPubKey)).Q.xOnly()
        // we use the standard BIP86 tweak
        val commonPubKey = internalPubKey.outputKey(Crypto.TaprootTweak.NoScriptTweak).first

        // this tx sends to a standard p2tr(commonPubKey) script
        val tx = Transaction(2, listOf(), listOf(TxOut(Satoshi(10000), Script.pay2tr(commonPubKey))), 0)

        // this is how Alice and Bob would spend that tx
        val spendingTx = Transaction(2, listOf(TxIn(OutPoint(tx, 0), sequence = 0)), listOf(TxOut(Satoshi(10000), Script.pay2wpkh(alicePubKey))), 0)

        val commonSig = run {
            val random = kotlin.random.Random.Default
            val aliceNonce = SecretNonce.generate(alicePrivKey, alicePubKey, commonPubKey, null, null, random.nextBytes(32).byteVector32())
            val bobNonce = SecretNonce.generate(bobPrivKey, bobPubKey, commonPubKey, null, null, random.nextBytes(32).byteVector32())

            val aggnonce = PublicNonce.aggregate(listOf(aliceNonce.publicNonce(), bobNonce.publicNonce()))
            val msg = Transaction.hashForSigningSchnorr(spendingTx, 0, listOf(tx.txOut[0]), SigHash.SIGHASH_DEFAULT, SigVersion.SIGVERSION_TAPROOT)

            // we use the same ctx for Alice and Bob, they both know all the public keys that are used here
            val ctx = SessionCtx(
                aggnonce,
                listOf(alicePubKey, bobPubKey),
                listOf(Pair(internalPubKey.tweak(Crypto.TaprootTweak.NoScriptTweak), true)),
                msg
            )
            val aliceSig = ctx.sign(aliceNonce, alicePrivKey)
            val bobSig = ctx.sign(bobNonce, bobPrivKey)
            ctx.partialSigAgg(listOf(aliceSig, bobSig))
        }

        // this tx looks like any other tx that spends a p2tr output, with a single signature
        val signedSpendingTx = spendingTx.updateWitness(0, ScriptWitness(listOf(commonSig)))
        Transaction.correctlySpends(signedSpendingTx, tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
}