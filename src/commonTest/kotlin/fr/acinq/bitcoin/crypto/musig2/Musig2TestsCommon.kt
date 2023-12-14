package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.reference.TransactionTestsCommon
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.*
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class Musig2TestsCommon {
    @Test
    fun `aggregate public keys`() {
        val tests = TransactionTestsCommon.readData("musig2/key_agg_vectors.json")
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = XonlyPublicKey(ByteVector32.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content))
            val (aggkey, _) = KeyAggCache.add(keyIndices.map { pubkeys[it] }, null)
            assertEquals(expected, aggkey)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertFails {
                var (_, cache) = KeyAggCache.add(keyIndices.map { pubkeys[it] }, null)
                tweakIndices.zip(isXonly).forEach { cache = cache.tweak(tweaks[it.first], it.second).first }
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
            //val expectedSecnonce = SecretNonce(it.jsonObject["expected_secnonce"]!!.jsonPrimitive.content)
            val expectedPubnonce = IndividualNonce(it.jsonObject["expected_pubnonce"]!!.jsonPrimitive.content)
            if (aggpk == null) {
                val (_, pubnonce) = SecretNonce.generate(randprime, sk, pk, msg?.byteVector32(), null, extraInput?.byteVector32())
                // assertEquals(expectedSecnonce, secnonce)
                assertEquals(expectedPubnonce, pubnonce)
            }
        }
    }

    @Test
    fun `aggregate nonces`() {
        val tests = TransactionTestsCommon.readData("musig2/nonce_agg_vectors.json")
        val nonces = tests.jsonObject["pnonces"]!!.jsonArray.map { IndividualNonce(it.jsonPrimitive.content) }
        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = AggregatedNonce(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val agg = IndividualNonce.aggregate(nonceIndices.map { nonces[it] })
            assertEquals(expected, agg)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertFails {
                IndividualNonce.aggregate(nonceIndices.map { nonces[it] })
            }
        }
    }

    @Test
    fun `aggregate signatures`() {
        val tests = TransactionTestsCommon.readData("musig2/sig_agg_vectors.json")
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { IndividualNonce(it.jsonPrimitive.content) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
        val psigs = tests.jsonObject["psigs"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
        val msg = ByteVector32.fromValidHex(tests.jsonObject["msg"]!!.jsonPrimitive.content)

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val psigIndices = it.jsonObject["psig_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = ByteVector64.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val aggnonce = IndividualNonce.aggregate(nonceIndices.map { pnonces[it] })
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertEquals(AggregatedNonce(it.jsonObject["aggnonce"]!!.jsonPrimitive.content), aggnonce)
            val cache = run {
                var (_, c) = KeyAggCache.add(keyIndices.map { pubkeys[it] }, null)
                tweakIndices.zip(isXonly).map { tweaks[it.first] to it.second }.forEach { (tweak, isXonly) ->
                    c = c.tweak(tweak, isXonly).first
                }
                c
            }
            val session = Session.build(aggnonce, msg, cache)
            val aggsig = session.add(psigIndices.map { psigs[it] })
            assertEquals(expected, aggsig)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val psigIndices = it.jsonObject["psig_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val aggnonce = IndividualNonce.aggregate(nonceIndices.map { pnonces[it] })
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertEquals(AggregatedNonce(it.jsonObject["aggnonce"]!!.jsonPrimitive.content), aggnonce)
            val cache = run {
                var (_, c) = KeyAggCache.add(keyIndices.map { pubkeys[it] }, null)
                tweakIndices.zip(isXonly).map { tweaks[it.first] to it.second }.forEach { (tweak, isXonly) ->
                    c = c.tweak(tweak, isXonly).first
                }
                c
            }
            val session = Session.build(aggnonce, msg, cache)
            assertFails {
                session.add(psigIndices.map { psigs[it] })
            }
        }
    }

    @Test
    fun `simple musig2 example`() {
        val random = Random.Default
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
            val nonces = privkeys.map {
                SecretNonce.generate(random.nextBytes(32).byteVector32(), it, it.publicKey(), null, null, null)
            }
            val secnonces = nonces.map { it.first }
            val pubnonces = nonces.map { it.second }

            // aggregate public nonces
            val aggnonce = IndividualNonce.aggregate(pubnonces)
            val cache = run {
                val (_, c) = KeyAggCache.add(pubkeys, null)
                val (c1, _) = c.tweak(plainTweak, false)
                val (c2, _) = c1.tweak(xonlyTweak, true)
                c2
            }
            val session = Session.build(aggnonce, msg, cache)
            // create partial signatures
            val psigs = privkeys.indices.map {
                session.sign(secnonces[it], privkeys[it], cache)
            }

            // verify partial signatures
            pubkeys.indices.forEach {
                assertTrue(session.verify(psigs[it], pubnonces[it], pubkeys[it], cache))
            }

            // aggregate partial signatures
            session.add(psigs)
        }

        // aggregate public keys
        val aggpub = run {
            val (_, c) = KeyAggCache.add(pubkeys, null)
            val (c1, _) = c.tweak(plainTweak, false)
            val (_, p) = c1.tweak(xonlyTweak, true)
            p
        }

        // check that the aggregated signature is a valid, plain Schnorr signature for the aggregated public key
        assertTrue(Crypto.verifySignatureSchnorr(msg, aggsig, aggpub.xOnly()))
    }

    @Test
    fun `use musig2 to replace multisig 2-of-2`() {
        val alicePrivKey = PrivateKey(ByteArray(32) { 1 })
        val alicePubKey = alicePrivKey.publicKey()
        val bobPrivKey = PrivateKey(ByteArray(32) { 2 })
        val bobPubKey = bobPrivKey.publicKey()

        // Alice and Bob exchange public keys and agree on a common aggregated key
        val (internalPubKey, cache) = KeyAggCache.add(listOf(alicePubKey, bobPubKey), null)
        // we use the standard BIP86 tweak
        val commonPubKey = internalPubKey.outputKey(Crypto.TaprootTweak.NoScriptTweak).first

        // this tx sends to a standard p2tr(commonPubKey) script
        val tx = Transaction(2, listOf(), listOf(TxOut(Satoshi(10000), Script.pay2tr(commonPubKey))), 0)

        // this is how Alice and Bob would spend that tx
        val spendingTx = Transaction(2, listOf(TxIn(OutPoint(tx, 0), sequence = 0)), listOf(TxOut(Satoshi(10000), Script.pay2wpkh(alicePubKey))), 0)

        val commonSig = run {
            val random = kotlin.random.Random.Default
            val aliceNonce = SecretNonce.generate(random.nextBytes(32).byteVector32(), alicePrivKey, alicePubKey, null, cache, null)
            val bobNonce = SecretNonce.generate(random.nextBytes(32).byteVector32(), bobPrivKey, bobPubKey, null, null, null)

            val aggnonce = IndividualNonce.aggregate(listOf(aliceNonce.second, bobNonce.second))
            val msg = Transaction.hashForSigningSchnorr(spendingTx, 0, listOf(tx.txOut[0]), SigHash.SIGHASH_DEFAULT, SigVersion.SIGVERSION_TAPROOT)

            // we use the same ctx for Alice and Bob, they both know all the public keys that are used here
            val (cache1, _) = cache.tweak(internalPubKey.tweak(Crypto.TaprootTweak.NoScriptTweak), true)
            val session = Session.build(aggnonce, msg, cache1)
            val aliceSig = session.sign(aliceNonce.first, alicePrivKey, cache1)
            val bobSig = session.sign(bobNonce.first, bobPrivKey, cache1)
            session.add(listOf(aliceSig, bobSig))
        }

        // this tx looks like any other tx that spends a p2tr output, with a single signature
        val signedSpendingTx = spendingTx.updateWitness(0, ScriptWitness(listOf(commonSig)))
        Transaction.correctlySpends(signedSpendingTx, tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `swap-in-potentiam example with musig2 and taproot`() {
        val userPrivateKey = PrivateKey(ByteArray(32) { 1 })
        val serverPrivateKey = PrivateKey(ByteArray(32) { 2 })
        val userRefundPrivateKey = PrivateKey(ByteArray(32) { 3 })
        val refundDelay = 25920

        val random = Random.Default

        // the redeem script is just the refund script. it is generated from this policy: and_v(v:pk(user),older(refundDelay))
        // it does not depend upon the user's or server's key, just the user's refund key and the refund delay
        val redeemScript = listOf(OP_PUSHDATA(userRefundPrivateKey.publicKey().xOnly()), OP_CHECKSIGVERIFY, OP_PUSHDATA(Script.encodeNumber(refundDelay)), OP_CHECKSEQUENCEVERIFY)
        val scriptTree = ScriptTree.Leaf(0, redeemScript)
        val merkleRoot = scriptTree.hash()

        // the internal pubkey is the musig2 aggregation of the user's and server's public keys: it does not depend upon the user's refund's key
        val (internalPubKey, cache) = KeyAggCache.add(listOf(userPrivateKey.publicKey(), serverPrivateKey.publicKey()), null)

        // it is tweaked with the script's merkle root to get the pubkey that will be exposed
        val pubkeyScript: List<ScriptElt> = Script.pay2tr(internalPubKey, merkleRoot)

        val swapInTx = Transaction(
            version = 2,
            txIn = listOf(),
            txOut = listOf(TxOut(Satoshi(10000), pubkeyScript)),
            lockTime = 0
        )

        // The transaction can be spent if the user and the server produce a signature.
        run {
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), sequence = TxIn.SEQUENCE_FINAL)),
                txOut = listOf(TxOut(Satoshi(10000), Script.pay2wpkh(userPrivateKey.publicKey()))),
                lockTime = 0
            )
            // this is the beginning of an interactive musig2 signing session. if user and server are disconnected before they have exchanged partial
            // signatures they will have to start again with fresh nonces
            val userNonce = SecretNonce.generate(random.nextBytes(32).byteVector32(), userPrivateKey, userPrivateKey.publicKey(), null, cache, null)
            val serverNonce = SecretNonce.generate(random.nextBytes(32).byteVector32(), serverPrivateKey, serverPrivateKey.publicKey(), null, cache, null)

            val txHash = Transaction.hashForSigningSchnorr(tx, 0, swapInTx.txOut, SigHash.SIGHASH_DEFAULT, SigVersion.SIGVERSION_TAPROOT)
            val commonNonce = IndividualNonce.aggregate(listOf(userNonce.second, serverNonce.second))

            val (cache1, _) = cache.tweak(internalPubKey.tweak(Crypto.TaprootTweak.ScriptTweak(merkleRoot)), true)
            val session = Session.build(commonNonce, txHash, cache1)
            val userSig = session.sign(userNonce.first, userPrivateKey, cache1)
            val serverSig = session.sign(serverNonce.first, serverPrivateKey, cache1)
            val commonSig = session.add(listOf(userSig, serverSig))
            val signedTx = tx.updateWitness(0, ScriptWitness(listOf(commonSig)))
            Transaction.correctlySpends(signedTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }

        // Or it can be spent with only the user's signature, after a delay.
        run {
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), sequence = refundDelay.toLong())),
                txOut = listOf(TxOut(Satoshi(10000), Script.pay2wpkh(userPrivateKey.publicKey()))),
                lockTime = 0
            )
            val sig = Crypto.signTaprootScriptPath(userRefundPrivateKey, tx, 0, swapInTx.txOut, SigHash.SIGHASH_DEFAULT, merkleRoot)
            val signedTx = tx.updateWitness(0, Script.witnessScriptPathPay2tr(internalPubKey, scriptTree, ScriptWitness(listOf(sig)), scriptTree))
            Transaction.correctlySpends(signedTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
    }
}