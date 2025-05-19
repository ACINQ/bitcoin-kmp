package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.reference.TransactionTestsCommon
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.*
import kotlin.random.Random
import kotlin.test.*

class Musig2TestsCommon {
    @Test
    fun `aggregate public keys`() {
        val tests = TestHelpers.readResourceAsJson("musig2/key_agg_vectors.json")
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = XonlyPublicKey(ByteVector32.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content))
            val (aggkey, _) = KeyAggCache.create(keyIndices.map { pubkeys[it] })
            assertEquals(expected, aggkey)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val tweakIndex = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }.firstOrNull()
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            when (tweakIndex) {
                null -> {
                    // One of the public keys is invalid, so key aggregation will fail.
                    // Callers must verify that public keys are valid before aggregating them.
                    assertFails {
                        KeyAggCache.create(keyIndices.map { pubkeys[it] })
                    }
                }
                else -> {
                    // The tweak cannot be applied, it would result in an invalid public key.
                    val (_, cache) = KeyAggCache.create(keyIndices.map { pubkeys[it] })
                    assertTrue(cache.tweak(tweaks[tweakIndex], isXonly[0]).isLeft)
                }
            }
        }
    }

    /** Secret nonces in test vectors use a custom encoding. */
    private fun deserializeSecretNonce(hex: String): SecretNonce {
        val serialized = Hex.decode(hex)
        require(serialized.size == 97) { "secret nonce from test vector should be serialized using 97 bytes" }
        // In test vectors, secret nonces are serialized as: <scalar_1> <scalar_2> <compressed_public_key>
        val compressedPublicKey = PublicKey.parse(serialized.takeLast(33).toByteArray())
        // We expect secret nonces serialized as: <magic> <scalar_1> <scalar_2> <public_key_x> <public_key_y>
        // Where we use a different endianness for the public key coordinates than the test vectors.
        val uncompressedPublicKey = compressedPublicKey.toUncompressedBin()
        val publicKeyX = uncompressedPublicKey.drop(1).take(32).reversed().toByteArray()
        val publicKeyY = uncompressedPublicKey.takeLast(32).reversed().toByteArray()
        val magic = Hex.decode("220EDCF1")
        return SecretNonce(magic + serialized.take(64) + publicKeyX + publicKeyY)
    }

    @Test
    fun `generate secret nonce`() {
        val tests = TestHelpers.readResourceAsJson("musig2/nonce_gen_vectors.json")
        tests.jsonObject["test_cases"]!!.jsonArray.forEach {
            val randprime = ByteVector32.fromValidHex(it.jsonObject["rand_"]!!.jsonPrimitive.content)
            val sk = it.jsonObject["sk"]?.jsonPrimitive?.contentOrNull?.let { PrivateKey.fromHex(it) }
            val pk = PublicKey.fromHex(it.jsonObject["pk"]!!.jsonPrimitive.content)
            val keyagg = it.jsonObject["aggpk"]?.jsonPrimitive?.contentOrNull?.let {
                // The test vectors directly provide an aggregated public key: we must manually create the corresponding
                // key aggregation cache to correctly test.
                val agg = XonlyPublicKey(ByteVector32.fromValidHex(it))
                val magic = Hex.decode("f4adbbdf")
                KeyAggCache(magic + agg.publicKey.toUncompressedBin().drop(1) + ByteArray(129) { 0x00 })
            }
            val msg = it.jsonObject["msg"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) }
            val extraInput = it.jsonObject["extra_in"]?.jsonPrimitive?.contentOrNull?.let { Hex.decode(it) }
            val expectedSecnonce = deserializeSecretNonce(it.jsonObject["expected_secnonce"]!!.jsonPrimitive.content)
            val expectedPubnonce = IndividualNonce(it.jsonObject["expected_pubnonce"]!!.jsonPrimitive.content)
            // secp256k1 only supports signing 32-byte messages (when provided), which excludes some of the test vectors.
            if (msg == null || msg.size == 32) {
                val (secnonce, pubnonce) = SecretNonce.generate(randprime, sk, pk, msg?.byteVector32(), keyagg, extraInput?.byteVector32())
                assertEquals(expectedPubnonce, pubnonce)
                assertEquals(expectedSecnonce, secnonce)
            }
        }
    }

    @Test
    fun `aggregate nonces`() {
        val tests = TestHelpers.readResourceAsJson("musig2/nonce_agg_vectors.json")
        val nonces = tests.jsonObject["pnonces"]!!.jsonArray.map { IndividualNonce(it.jsonPrimitive.content) }
        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = AggregatedNonce(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val agg = IndividualNonce.aggregate(nonceIndices.map { nonces[it] }).right
            assertNotNull(agg)
            assertEquals(expected, agg)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val nonceIndices = it.jsonObject["pnonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertTrue(IndividualNonce.aggregate(nonceIndices.map { nonces[it] }).isLeft)
        }
    }

    @Test
    fun sign() {
        val tests = TestHelpers.readResourceAsJson("musig2/sign_verify_vectors.json")
        val sk = PrivateKey.fromHex(tests.jsonObject["sk"]!!.jsonPrimitive.content)
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val secnonces = tests.jsonObject["secnonces"]!!.jsonArray.map { deserializeSecretNonce(it.jsonPrimitive.content) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { IndividualNonce(it.jsonPrimitive.content) }
        val aggnonces = tests.jsonObject["aggnonces"]!!.jsonArray.map { AggregatedNonce(it.jsonPrimitive.content) }
        val msgs = tests.jsonObject["msgs"]!!.jsonArray.map { ByteVector(it.jsonPrimitive.content) }

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = ByteVector32.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content)
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val messageIndex = it.jsonObject["msg_index"]!!.jsonPrimitive.int
            val aggnonce = IndividualNonce.aggregate(nonceIndices.map { pnonces[it] }).right
            assertNotNull(aggnonce)
            assertEquals(aggnonces[it.jsonObject["aggnonce_index"]!!.jsonPrimitive.int], aggnonce)
            val keyagg = KeyAggCache.create(keyIndices.map { pubkeys[it] }).second
            // We only support signing 32-byte messages.
            if (msgs[messageIndex].bytes.size == 32) {
                val session = Session.create(aggnonce, ByteVector32(msgs[messageIndex]), keyagg)
                assertNotNull(session)
                val psig = session.sign(secnonces[keyIndices[signerIndex]], sk)
                assertEquals(expected, psig)
                assertTrue(session.verify(psig, pnonces[nonceIndices[signerIndex]], pubkeys[keyIndices[signerIndex]]))
            }
        }
        tests.jsonObject["verify_fail_test_cases"]!!.jsonArray.forEach {
            val psig = Hex.decode(it.jsonObject["sig"]!!.jsonPrimitive.content).byteVector32()
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val messageIndex = it.jsonObject["msg_index"]!!.jsonPrimitive.int
            if (msgs[messageIndex].bytes.size == 32) {
                val aggnonce = IndividualNonce.aggregate(nonceIndices.map { pnonces[it] }).right
                assertNotNull(aggnonce)
                val (_, keyagg) = KeyAggCache.create(keyIndices.map { pubkeys[it] })
                val session = Session.create(aggnonce, ByteVector32(msgs[messageIndex]), keyagg)
                assertNotNull(session)
                assertFalse(session.verify(psig, pnonces[signerIndex], pubkeys[signerIndex]))
            }
        }
    }

    @Test
    fun `aggregate signatures`() {
        val tests = TestHelpers.readResourceAsJson("musig2/sig_agg_vectors.json")
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
            val aggnonce = IndividualNonce.aggregate(nonceIndices.map { pnonces[it] }).right
            assertNotNull(aggnonce)
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertEquals(AggregatedNonce(it.jsonObject["aggnonce"]!!.jsonPrimitive.content), aggnonce)
            val keyagg = tweakIndices
                .zip(isXonly)
                .map { tweaks[it.first] to it.second }
                .fold(KeyAggCache.create(keyIndices.map { pubkeys[it] }).second) { agg, (tweak, isXonly) -> agg.tweak(tweak, isXonly).right!!.first }
            val session = Session.create(aggnonce, msg, keyagg)
            val aggsig = session.aggregateSigs(psigIndices.map { psigs[it] }).right
            assertEquals(expected, aggsig)
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val psigIndices = it.jsonObject["psig_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val aggnonce = IndividualNonce.aggregate(nonceIndices.map { pnonces[it] }).right
            assertNotNull(aggnonce)
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            assertEquals(AggregatedNonce(it.jsonObject["aggnonce"]!!.jsonPrimitive.content), aggnonce)
            val keyagg = tweakIndices
                .zip(isXonly)
                .map { tweaks[it.first] to it.second }
                .fold(KeyAggCache.create(keyIndices.map { pubkeys[it] }).second) { agg, (tweak, isXonly) -> agg.tweak(tweak, isXonly).right!!.first }
            val session = Session.create(aggnonce, msg, keyagg)
            assertTrue(session.aggregateSigs(psigIndices.map { psigs[it] }).isLeft)
        }
    }

    @Test
    fun `tweak tests`() {
        val tests = TestHelpers.readResourceAsJson("musig2/tweak_vectors.json")
        val sk = PrivateKey.fromHex(tests.jsonObject["sk"]!!.jsonPrimitive.content)
        val pubkeys = tests.jsonObject["pubkeys"]!!.jsonArray.map { PublicKey(ByteVector(it.jsonPrimitive.content)) }
        val pnonces = tests.jsonObject["pnonces"]!!.jsonArray.map { IndividualNonce(it.jsonPrimitive.content) }
        val tweaks = tests.jsonObject["tweaks"]!!.jsonArray.map { ByteVector32.fromValidHex(it.jsonPrimitive.content) }
        val msg = ByteVector32.fromValidHex(tests.jsonObject["msg"]!!.jsonPrimitive.content)

        val secnonce = deserializeSecretNonce(tests.jsonObject["secnonce"]!!.jsonPrimitive.content)
        val aggnonce = AggregatedNonce(tests.jsonObject["aggnonce"]!!.jsonPrimitive.content)

        assertEquals(pubkeys[0], sk.publicKey())
        assertEquals(aggnonce, IndividualNonce.aggregate(listOf(pnonces[0], pnonces[1], pnonces[2])).right)

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val expected = ByteVector32.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content)
            assertEquals(aggnonce, IndividualNonce.aggregate(nonceIndices.map { pnonces[it] }).right)
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val keyagg = tweakIndices.fold(KeyAggCache.create(keyIndices.map { pubkeys[it] }).second) { keyAgg, tweakIdx -> keyAgg.tweak(tweaks[tweakIdx], isXonly[tweakIdx]).right!!.first }
            val session = Session.create(aggnonce, msg, keyagg)
            assertNotNull(session)
            val psig = session.sign(secnonce, sk)
            assertEquals(expected, psig)
            assertTrue(session.verify(psig, pnonces[nonceIndices[signerIndex]], pubkeys[keyIndices[signerIndex]]))
        }
        tests.jsonObject["error_test_cases"]!!.jsonArray.forEach {
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val nonceIndices = it.jsonObject["nonce_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertEquals(aggnonce, IndividualNonce.aggregate(nonceIndices.map { pnonces[it] }).right)
            val tweakIndices = it.jsonObject["tweak_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertEquals(1, tweakIndices.size)
            val tweak = tweaks[tweakIndices.first()]
            val isXonly = it.jsonObject["is_xonly"]!!.jsonArray.map { it.jsonPrimitive.boolean }.first()
            val (_, keyagg) = KeyAggCache.create(keyIndices.map { pubkeys[it] })
            assertTrue(keyagg.tweak(tweak, isXonly).isLeft)
        }
    }

    @Test
    fun `simple musig2 example`() {
        val msg = Random.Default.nextBytes(32).byteVector32()
        val privkeys = listOf(
            PrivateKey(ByteArray(32) { 1 }),
            PrivateKey(ByteArray(32) { 2 }),
            PrivateKey(ByteArray(32) { 3 }),
        )
        val pubkeys = privkeys.map { it.publicKey() }

        val plainTweak = ByteVector32("this could be a BIP32 tweak....".encodeToByteArray() + ByteArray(1))
        val xonlyTweak = ByteVector32("this could be a taproot tweak..".encodeToByteArray() + ByteArray(1))

        // Aggregate public keys from all participants, and apply tweaks.
        val (keyAggCache, aggpub) = run {
            val (_, c) = KeyAggCache.create(pubkeys)
            val (c1, _) = c.tweak(plainTweak, false).right!!
            c1.tweak(xonlyTweak, true).right!!
        }

        // Generate secret nonces for each participant.
        val nonces = privkeys.map { SecretNonce.generate(Random.Default.nextBytes(32).byteVector32(), it, it.publicKey(), message = null, keyAggCache, extraInput = null) }
        val secnonces = nonces.map { it.first }
        val pubnonces = nonces.map { it.second }

        // Aggregate public nonces.
        val aggnonce = IndividualNonce.aggregate(pubnonces).right
        assertNotNull(aggnonce)

        // Create partial signatures from each participant.
        val session = Session.create(aggnonce, msg, keyAggCache)
        val psigs = privkeys.indices.map { session.sign(secnonces[it], privkeys[it]) }
        // Verify individual partial signatures.
        pubkeys.indices.forEach { assertTrue(session.verify(psigs[it], pubnonces[it], pubkeys[it])) }
        // Aggregate partial signatures into a single signature.
        val aggsig = session.aggregateSigs(psigs).right
        assertNotNull(aggsig)
        // Check that the aggregated signature is a valid, plain Schnorr signature for the aggregated public key.
        assertTrue(Crypto.verifySignatureSchnorr(msg, aggsig, aggpub.xOnly()))
    }

    @Test
    fun `use musig2 to replace multisig 2-of-2`() {
        val alicePrivKey = PrivateKey(ByteArray(32) { 1 })
        val alicePubKey = alicePrivKey.publicKey()
        val bobPrivKey = PrivateKey(ByteArray(32) { 2 })
        val bobPubKey = bobPrivKey.publicKey()

        // Alice and Bob exchange public keys and agree on a common aggregated key.
        val internalPubKey = Musig2.aggregateKeys(listOf(alicePubKey, bobPubKey))
        val commonPubKey = internalPubKey.outputKey(Crypto.TaprootTweak.NoScriptTweak).first

        // This tx sends to a taproot script that doesn't contain any script path.
        val tx = Transaction(2, listOf(), listOf(TxOut(10_000.sat(), Script.pay2tr(commonPubKey))), 0)
        // This tx spends the previous tx with Alice and Bob's signatures.
        val spendingTx = Transaction(2, listOf(TxIn(OutPoint(tx, 0), sequence = 0)), listOf(TxOut(10_000.sat(), Script.pay2wpkh(alicePubKey))), 0)

        // The first step of a musig2 signing session is to exchange nonces.
        // If participants are disconnected before the end of the signing session, they must start again with fresh nonces.
        val aliceNonce = Musig2.generateNonce(Random.Default.nextBytes(32).byteVector32(), alicePrivKey, listOf(alicePubKey, bobPubKey))
        val bobNonce = Musig2.generateNonce(Random.Default.nextBytes(32).byteVector32(), bobPrivKey, listOf(alicePubKey, bobPubKey))

        // Once they have each other's public nonce, they can produce partial signatures.
        val publicNonces = listOf(aliceNonce.second, bobNonce.second)

        val aliceSig = Musig2.signTaprootInput(alicePrivKey, spendingTx, 0, listOf(tx.txOut[0]), listOf(alicePubKey, bobPubKey), aliceNonce.first, publicNonces, scriptTree = null).right
        assertNotNull(aliceSig)
        assertTrue(Musig2.verifyTaprootSignature(aliceSig, aliceNonce.second, alicePubKey, spendingTx, 0, listOf(tx.txOut[0]), listOf(alicePubKey, bobPubKey), publicNonces, scriptTree = null))

        val bobSig = Musig2.signTaprootInput(bobPrivKey, spendingTx, 0, listOf(tx.txOut[0]), listOf(alicePubKey, bobPubKey), bobNonce.first, publicNonces, scriptTree = null).right
        assertNotNull(bobSig)
        assertTrue(Musig2.verifyTaprootSignature(bobSig, bobNonce.second, bobPubKey, spendingTx, 0, listOf(tx.txOut[0]), listOf(alicePubKey, bobPubKey), publicNonces, scriptTree = null))

        // Once they have each other's partial signature, they can aggregate them into a valid signature.
        val aggregateSig = Musig2.aggregateTaprootSignatures(listOf(aliceSig, bobSig), spendingTx, 0, listOf(tx.txOut[0]), listOf(alicePubKey, bobPubKey), publicNonces, scriptTree = null).right
        assertNotNull(aggregateSig)

        // This tx looks like any other tx that spends a p2tr output, with a single signature.
        val signedSpendingTx = spendingTx.updateWitness(0, Script.witnessKeyPathPay2tr(aggregateSig))
        Transaction.correctlySpends(signedSpendingTx, tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `swap-in-potentiam example with musig2 and taproot`() {
        val userPrivateKey = PrivateKey(ByteArray(32) { 1 })
        val userPublicKey = userPrivateKey.publicKey()
        val serverPrivateKey = PrivateKey(ByteArray(32) { 2 })
        val serverPublicKey = serverPrivateKey.publicKey()
        val userRefundPrivateKey = PrivateKey(ByteArray(32) { 3 })
        val refundDelay = 25920

        // The redeem script is just the refund script, generated from this policy: and_v(v:pk(user),older(refundDelay))
        // It does not depend upon the user's or server's key, just the user's refund key and the refund delay.
        val redeemScript = listOf(OP_PUSHDATA(userRefundPrivateKey.xOnlyPublicKey()), OP_CHECKSIGVERIFY, OP_PUSHDATA(Script.encodeNumber(refundDelay)), OP_CHECKSEQUENCEVERIFY)
        val scriptTree = ScriptTree.Leaf(redeemScript)

        // The internal pubkey is the musig2 aggregation of the user's and server's public keys: it does not depend upon the user's refund's key.
        val internalPubKey = Musig2.aggregateKeys(listOf(userPublicKey, serverPublicKey))
        // It is tweaked with the script's merkle root to get the pubkey that will be exposed.
        val pubkeyScript = Script.pay2tr(internalPubKey, scriptTree)

        val swapInTx = Transaction(
            version = 2,
            txIn = listOf(),
            txOut = listOf(TxOut(10_000.sat(), pubkeyScript)),
            lockTime = 0
        )

        // The transaction can be spent if the user and the server produce a signature.
        run {
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), sequence = TxIn.SEQUENCE_FINAL)),
                txOut = listOf(TxOut(10_000.sat(), Script.pay2wpkh(userPublicKey))),
                lockTime = 0
            )
            // The first step of a musig2 signing session is to exchange nonces.
            // If participants are disconnected before the end of the signing session, they must start again with fresh nonces.
            val userNonce = Musig2.generateNonce(Random.Default.nextBytes(32).byteVector32(), userPrivateKey, listOf(userPublicKey, serverPublicKey))
            val serverNonce = Musig2.generateNonce(Random.Default.nextBytes(32).byteVector32(), serverPrivateKey, listOf(userPublicKey, serverPublicKey))

            // Once they have each other's public nonce, they can produce partial signatures.
            val publicNonces = listOf(userNonce.second, serverNonce.second)
            val userSig = Musig2.signTaprootInput(userPrivateKey, tx, 0, swapInTx.txOut, listOf(userPublicKey, serverPublicKey), userNonce.first, publicNonces, scriptTree).right
            assertNotNull(userSig)
            assertTrue(Musig2.verifyTaprootSignature(userSig, userNonce.second, userPublicKey, tx, 0, swapInTx.txOut, listOf(userPublicKey, serverPublicKey), publicNonces, scriptTree))

            val serverSig = Musig2.signTaprootInput(serverPrivateKey, tx, 0, swapInTx.txOut, listOf(userPublicKey, serverPublicKey), serverNonce.first, publicNonces, scriptTree).right
            assertNotNull(serverSig)
            assertTrue(Musig2.verifyTaprootSignature(serverSig, serverNonce.second, serverPublicKey, tx, 0, swapInTx.txOut, listOf(userPublicKey, serverPublicKey), publicNonces, scriptTree))

            // Once they have each other's partial signature, they can aggregate them into a valid signature.
            val aggregateSig = Musig2.aggregateTaprootSignatures(listOf(userSig, serverSig), tx, 0, swapInTx.txOut, listOf(userPublicKey, serverPublicKey), publicNonces, scriptTree).right
            assertNotNull(aggregateSig)
            val signedTx = tx.updateWitness(0, Script.witnessKeyPathPay2tr(aggregateSig))
            Transaction.correctlySpends(signedTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }

        // Or it can be spent with only the user's signature, after a delay.
        run {
            val tx = Transaction(
                version = 2,
                txIn = listOf(TxIn(OutPoint(swapInTx, 0), sequence = refundDelay.toLong())),
                txOut = listOf(TxOut(10_000.sat(), Script.pay2wpkh(userPublicKey))),
                lockTime = 0
            )
            val sig = Transaction.signInputTaprootScriptPath(userRefundPrivateKey, tx, 0, swapInTx.txOut, SigHash.SIGHASH_DEFAULT, scriptTree.hash())
            val signedTx = tx.updateWitness(0, Script.witnessScriptPathPay2tr(internalPubKey, scriptTree, ScriptWitness(listOf(sig)), scriptTree))
            Transaction.correctlySpends(signedTx, swapInTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        }
    }
}