package fr.acinq.bitcoin

import kotlinx.serialization.InternalSerializationApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@ExperimentalStdlibApi
@InternalSerializationApi
class ScriptTestsCommon {
    val priv = PrivateKey(Hex.decode("0101010101010101010101010101010101010101010101010101010101010101"))
    val pub = priv.publicKey()

    @Test
    fun `p2pkh`() {
        val script = Script.pay2pkh(pub)
        assertEquals("76a91479b000887626b294a914501a4cd226b58b23598388ac", Hex.encode(Script.write(script)))
        assertTrue { Script.isPay2pkh(script) }
        assertFalse { Script.isPay2sh(script) || Script.isPay2wpkh(script) || Script.isPay2wsh(script) }
    }

    @Test
    fun `p2sh`() {
        val script = Script.pay2sh(Script.pay2pkh(pub))
        assertEquals("a914832e012d4cd5f23df82efd34e473345a2f8aa4fb87", Hex.encode(Script.write(script)))
        assertTrue { Script.isPay2sh(script) }
        assertFalse { Script.isPay2pkh(script) || Script.isPay2wpkh(script) || Script.isPay2wsh(script) }
    }

    @Test
    fun `p2wpkh`() {
        val script = Script.pay2wpkh(pub)
        assertEquals("001479b000887626b294a914501a4cd226b58b235983", Hex.encode(Script.write(script)))
        assertTrue { Script.isPay2wpkh(script) }
        assertFalse { Script.isPay2sh(script) || Script.isPay2pkh(script) || Script.isPay2wsh(script) }
    }

    @Test
    fun `p2wsh`() {
        val script = Script.pay2wsh(Script.pay2pkh(pub))
        assertEquals("00206f1b349d7fed5240ad719948529e8b06abf038438f9b523820489375af513a3f", Hex.encode(Script.write(script)))
        assertTrue { Script.isPay2wsh(script) }
        assertFalse { Script.isPay2sh(script) || Script.isPay2wpkh(script) || Script.isPay2pkh(script) }
    }
}