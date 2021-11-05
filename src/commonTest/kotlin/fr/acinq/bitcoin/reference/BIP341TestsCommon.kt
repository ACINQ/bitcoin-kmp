package fr.acinq.bitcoin.reference

import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals

class BIP341TestsCommon {
    @Test
    fun `BIP341 reference tests (key path spending)`() {
        val tests = TransactionTestsCommon.readData("data/bip341_wallet_vectors.json").jsonObject["keyPathSpending"]!!
        tests.jsonArray.forEach { it ->
            //val fulledSignedTx = Transaction.read(it.jsonObject["auxiliary"]!!.jsonObject["fulledSignedTx"]!!.jsonPrimitive.content)
            val rawUnsignedTx = Transaction.read(it.jsonObject["given"]!!.jsonObject["rawUnsignedTx"]!!.jsonPrimitive.content)
            val utxosSpent = it.jsonObject["given"]!!.jsonObject["utxosSpent"]!!.jsonArray.map {
                TxOut(it.jsonObject["amountSats"]!!.jsonPrimitive.long.sat(), Hex.decode(it.jsonObject["scriptPubKey"]!!.jsonPrimitive.content))
            }
            val hashAmounts = it.jsonObject["intermediary"]!!.jsonObject["hashAmounts"]!!.jsonPrimitive.content
            val hashOutputs = it.jsonObject["intermediary"]!!.jsonObject["hashOutputs"]!!.jsonPrimitive.content
            val hashPrevouts = it.jsonObject["intermediary"]!!.jsonObject["hashPrevouts"]!!.jsonPrimitive.content
            val hashScriptPubkeys = it.jsonObject["intermediary"]!!.jsonObject["hashScriptPubkeys"]!!.jsonPrimitive.content
            val hashSequences = it.jsonObject["intermediary"]!!.jsonObject["hashSequences"]!!.jsonPrimitive.content

            assertEquals(hashAmounts, Hex.encode(Transaction.amountsSha256(utxosSpent)))
            assertEquals(hashOutputs, Hex.encode(Transaction.outputsSha256(rawUnsignedTx)))
            assertEquals(hashPrevouts, Hex.encode(Transaction.prevoutsSha256(rawUnsignedTx)))
            assertEquals(hashScriptPubkeys, Hex.encode(Transaction.scriptPubkeysSha256(utxosSpent)))
            assertEquals(hashSequences, Hex.encode(Transaction.sequencesSha256(rawUnsignedTx)))

            it.jsonObject["inputSpending"]!!.jsonArray.forEach {
                val given = it.jsonObject["given"]!!.jsonObject
                val hashType = given["hashType"]!!.jsonPrimitive.int
                val txinIndex = given["txinIndex"]!!.jsonPrimitive.int
                val internalPrivkey = PrivateKey.fromHex(given["internalPrivkey"]!!.jsonPrimitive.content)
                val merkleRoot = nullOrBytes(given["merkleRoot"]?.jsonPrimitive?.content)

                val internalPubkey = XonlyPublicKey(internalPrivkey.publicKey())
                val intermediary = it.jsonObject["intermediary"]!!.jsonObject
                assertEquals(ByteVector32(intermediary["internalPubkey"]!!.jsonPrimitive.content), internalPubkey.value)
                assertEquals(ByteVector32(intermediary["tweak"]!!.jsonPrimitive.content), internalPubkey.tweak(merkleRoot))

                val tweakedPrivateKey = internalPrivkey.tweak(internalPubkey.tweak(merkleRoot))
                assertEquals(ByteVector32(intermediary["tweakedPrivkey"]!!.jsonPrimitive.content), tweakedPrivateKey.value)

                val hash = Transaction.hashForSigningSchnorr(rawUnsignedTx, txinIndex, utxosSpent, hashType)
                assertEquals(ByteVector32(intermediary["sigHash"]!!.jsonPrimitive.content), hash)

                val sig = Secp256k1.signSchnorr(hash.toByteArray(), tweakedPrivateKey.value.toByteArray(), Hex.decode("0000000000000000000000000000000000000000000000000000000000000000"))
                val witness = when (hashType) {
                    SigHash.SIGHASH_DEFAULT -> sig.byteVector()
                    else -> (sig + byteArrayOf(hashType.toByte())).byteVector()
                }
                val expected = it.jsonObject["expected"]!!.jsonObject
                val witnessStack = expected["witness"]!!.jsonArray.map { ByteVector(it.jsonPrimitive.content) }
                assertEquals(1, witnessStack.size)
                assertEquals(witnessStack.first(), witness)
            }
        }
    }

    fun nullOrBytes(input: String?): ByteVector32? = when (input) {
        null, "null" -> null
        else -> ByteVector32(input)
    }
}