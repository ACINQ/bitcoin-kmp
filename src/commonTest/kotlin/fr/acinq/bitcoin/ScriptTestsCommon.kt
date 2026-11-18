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
import kotlin.test.*

class ScriptTestsCommon {
    private val priv = PrivateKey.fromHex("0101010101010101010101010101010101010101010101010101010101010101")
    private val pub = priv.publicKey()

    @Test
    fun p2pkh() {
        val script = Script.pay2pkh(pub)
        assertEquals("76a91479b000887626b294a914501a4cd226b58b23598388ac", Hex.encode(Script.write(script)))
        assertTrue(Script.isPay2pkh(script))
        assertNull(Script.getWitnessVersion(script))
        assertFalse(Script.isPay2sh(script) || Script.isPay2wpkh(script) || Script.isPay2wsh(script))
        assertEquals("1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD", Bitcoin.addressFromPublicKeyScript(Block.LivenetGenesisBlock.hash, script).right)
    }

    @Test
    fun p2sh() {
        val script = Script.pay2sh(Script.pay2pkh(pub))
        assertEquals("a914832e012d4cd5f23df82efd34e473345a2f8aa4fb87", Hex.encode(Script.write(script)))
        assertTrue(Script.isPay2sh(script))
        assertNull(Script.getWitnessVersion(script))
        assertFalse(Script.isPay2pkh(script) || Script.isPay2wpkh(script) || Script.isPay2wsh(script))
        assertEquals("3DedZ8SErqfunkjqnv8Pta1MKgEuHi22W5", Bitcoin.addressFromPublicKeyScript(Block.LivenetGenesisBlock.hash, script).right)
    }

    @Test
    fun p2wpkh() {
        val script = Script.pay2wpkh(pub)
        assertEquals("001479b000887626b294a914501a4cd226b58b235983", Hex.encode(Script.write(script)))
        assertTrue(Script.isPay2wpkh(script))
        assertEquals(0, Script.getWitnessVersion(script))
        assertFalse(Script.isPay2sh(script) || Script.isPay2pkh(script) || Script.isPay2wsh(script))
        assertEquals("bc1q0xcqpzrky6eff2g52qdye53xkk9jxkvrh6yhyw", Bitcoin.addressFromPublicKeyScript(Block.LivenetGenesisBlock.hash, script).right)
    }

    @Test
    fun p2wsh() {
        val script = Script.pay2wsh(Script.pay2pkh(pub))
        assertEquals("00206f1b349d7fed5240ad719948529e8b06abf038438f9b523820489375af513a3f", Hex.encode(Script.write(script)))
        assertTrue(Script.isPay2wsh(script))
        assertEquals(0, Script.getWitnessVersion(script))
        assertFalse(Script.isPay2sh(script) || Script.isPay2wpkh(script) || Script.isPay2pkh(script))
        assertEquals("bc1qdudnf8tla4fyptt3n9y9985tq64lqwzr37d4ywpqfzfhtt638glsqaednx", Bitcoin.addressFromPublicKeyScript(Block.LivenetGenesisBlock.hash, script).right)
    }

    @Test
    fun `future segwit versions`() {
        val script = Script.parse("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        assertEquals("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", Hex.encode(Script.write(script)))
        assertTrue(Script.isNativeWitnessScript(script))
        assertFalse(Script.isPay2sh(script) || Script.isPay2wsh(script) || Script.isPay2wpkh(script) || Script.isPay2pkh(script))
        assertEquals(1, Script.getWitnessVersion(script))
        assertEquals("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", Bitcoin.addressFromPublicKeyScript(Block.LivenetGenesisBlock.hash, script).right)
    }

    @Test
    fun `script type checks on raw bytes`() {
        // Byte-level checks match the exact canonical encoding (like Bitcoin Core), and never throw.
        val p2pkh = Script.write(Script.pay2pkh(pub))
        val p2sh = Script.write(Script.pay2sh(Script.pay2pkh(pub)))
        val p2wpkh = Script.write(Script.pay2wpkh(pub))
        val p2wsh = Script.write(Script.pay2wsh(Script.pay2pkh(pub)))
        val p2tr = Script.write(Script.pay2tr(pub.xOnly(), Crypto.TaprootTweak.KeyPathTweak))
        val p2a = Script.write(Script.pay2anchor)

        // Same script, with the push at pushIndex encoded with OP_PUSHDATA1.
        fun nonCanonical(script: ByteArray, pushIndex: Int = 1): ByteArray =
            script.copyOfRange(0, pushIndex) + OP_PUSHDATA1.code.toByte() + script.copyOfRange(pushIndex, script.size)

        // Truncated in the middle of the push at pushIndex: cannot be parsed.
        fun truncated(script: ByteArray, pushIndex: Int = 1): ByteArray = script.copyOfRange(0, pushIndex + 2)

        assertTrue(Script.isPay2pkh(p2pkh))
        assertFalse(Script.isPay2pkh(nonCanonical(p2pkh, pushIndex = 2)))
        assertFalse(Script.isPay2pkh(truncated(p2pkh, pushIndex = 2)))
        assertFalse(Script.isPay2pkh(p2pkh + OP_NOP.code.toByte()))
        assertFalse(Script.isPay2pkh(ByteArray(0)))

        assertTrue(Script.isPay2sh(p2sh))
        assertFalse(Script.isPay2sh(nonCanonical(p2sh)))
        assertFalse(Script.isPay2sh(truncated(p2sh)))
        assertFalse(Script.isPay2sh(p2sh + OP_NOP.code.toByte()))
        assertFalse(Script.isPay2sh(ByteArray(0)))

        assertTrue(Script.isPay2wpkh(p2wpkh))
        assertFalse(Script.isPay2wpkh(nonCanonical(p2wpkh)))
        assertFalse(Script.isPay2wpkh(truncated(p2wpkh)))
        assertFalse(Script.isPay2wpkh(p2wpkh + OP_NOP.code.toByte()))
        assertFalse(Script.isPay2wpkh(ByteArray(0)))

        assertTrue(Script.isPay2wsh(p2wsh))
        assertFalse(Script.isPay2wsh(nonCanonical(p2wsh)))
        assertFalse(Script.isPay2wsh(truncated(p2wsh)))
        assertFalse(Script.isPay2wsh(p2wsh + OP_NOP.code.toByte()))
        assertFalse(Script.isPay2wsh(ByteArray(0)))

        assertTrue(Script.isPay2tr(p2tr))
        assertTrue(Script.isPay2tr(p2tr.byteVector()))
        assertFalse(Script.isPay2tr(nonCanonical(p2tr)))
        assertFalse(Script.isPay2tr(nonCanonical(p2tr).byteVector()))
        assertFalse(Script.isPay2tr(truncated(p2tr)))
        assertFalse(Script.isPay2tr(truncated(p2tr).byteVector()))
        assertFalse(Script.isPay2tr(p2tr + OP_NOP.code.toByte()))
        assertFalse(Script.isPay2tr(ByteArray(0)))

        assertTrue(Script.isPay2Anchor(p2a))
        assertTrue(Script.isPay2Anchor(p2a.byteVector()))
        assertFalse(Script.isPay2Anchor(nonCanonical(p2a)))
        assertFalse(Script.isPay2Anchor(nonCanonical(p2a).byteVector()))
        assertFalse(Script.isPay2Anchor(truncated(p2a)))
        assertFalse(Script.isPay2Anchor(truncated(p2a).byteVector()))
        assertFalse(Script.isPay2Anchor(p2a + OP_NOP.code.toByte()))
        assertFalse(Script.isPay2Anchor(ByteArray(0)))

        // The List<ScriptElt> overloads are more lenient and accept non-canonical pushes.
        assertTrue(Script.isPay2pkh(Script.parse(nonCanonical(p2pkh, pushIndex = 2))))
        assertTrue(Script.isPay2sh(Script.parse(nonCanonical(p2sh))))
        assertTrue(Script.isPay2wpkh(Script.parse(nonCanonical(p2wpkh))))
        assertTrue(Script.isPay2wsh(Script.parse(nonCanonical(p2wsh))))
        assertTrue(Script.isPay2tr(Script.parse(nonCanonical(p2tr))))
    }

    @Test
    fun `parse if - else - endif`() {
        val tx = Transaction(
            version = 1,
            txIn = listOf(TxIn(OutPoint(TxHash(ByteVector32.Zeroes), 0xffffffff), Script.write(listOf(OP_NOP)), 0xffffffff)),
            txOut = listOf(TxOut(0x12a05f200L.sat(), ByteVector.empty)),
            lockTime = 0
        )
        val ctx = Script.Context(tx, 0, 0.sat(), listOf())
        val runner = Script.Runner(ctx)
        val script = listOf(OP_1, OP_2, OP_EQUAL, OP_IF, OP_3, OP_ELSE, OP_4, OP_ENDIF)
        val stack = runner.run(script, SigVersion.SIGVERSION_BASE)
        assertEquals(stack, listOf(ByteVector("04")))
        val script1 = listOf(OP_1, OP_1, OP_EQUAL, OP_IF, OP_3, OP_ELSE, OP_4, OP_ENDIF)
        val stack1 = runner.run(script1, SigVersion.SIGVERSION_BASE)
        assertEquals(stack1, listOf(ByteVector("03")))
        val script2 = listOf(OP_1, OP_1, OP_EQUAL, OP_IF, OP_3, OP_3, OP_EQUAL, OP_IF, OP_5, OP_ENDIF, OP_ELSE, OP_4, OP_ENDIF)
        val stack2 = runner.run(script2, SigVersion.SIGVERSION_BASE)
        assertEquals(stack2, listOf(ByteVector("05")))
    }

    @Test
    fun `encode - decode simple numbers`() {
        for (i in -1..16) {
            assertEquals(i.toLong(), Script.decodeNumber(Script.encodeNumber(i), checkMinimalEncoding = true))
        }
    }
}