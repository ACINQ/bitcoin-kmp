package fr.acinq.bitcoin

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import fr.acinq.bitcoin.MnemonicCode.toMnemonics
import fr.acinq.bitcoin.MnemonicCode.toSeed
import org.junit.Test
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFails

@ExperimentalStdlibApi
class MnemonicCodeTestsJvm {
    val mapper = jacksonObjectMapper()

    @Test
    fun `to seed`() {
        val mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val passphrase = ""
        val seed = MnemonicCode.toSeed(mnemonics, passphrase)
        assertEquals("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4", Hex.encode(seed))
    }

    @Test
    fun `reference tests`() {
        val stream = javaClass.getResourceAsStream("/bip39_vectors.json")
        val tests = mapper.readValue<TestVectors>(stream)

        tests.english.map { it ->
            val raw = it[0]
            val mnemonics = it[1]
            val seed = it[2]
            assertEquals(toMnemonics(Hex.decode(raw)).joinToString(" "), mnemonics)
            assertEquals(Hex.encode(toSeed(toMnemonics(Hex.decode(raw)), "TREZOR")), seed)
        }
    }

    @Test
    fun `validate mnemonics(valid)`() {
        val random = Random()

        for (i in 0..99) {
            for (length in listOf(16, 20, 24, 28, 32, 36, 40)) {
                val entropy = ByteArray(length)
                random.nextBytes(entropy)
                val mnemonics = MnemonicCode.toMnemonics(entropy)
                MnemonicCode.validate(mnemonics)
            }
        }
    }

    @Test
    fun `validate mnemonics (invalid)`() {
        val invalidMnemonics = listOf(
            "",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow", // one word missing
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog fog", // one extra word
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fig" // wrong word
        )
        invalidMnemonics.map { it ->
            assertFails {
                MnemonicCode.validate(it)
            }
        }
    }

    companion object {
        data class TestVectors(val english: List<List<String>>)
    }

}