package fr.acinq.bitcoin.reference

import fr.acinq.bitcoin.DeterministicWallet
import fr.acinq.bitcoin.MnemonicCode.toSeed
import fr.acinq.bitcoin.TestHelpers
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class BIP32KeyFingerprintTestsCommon {
    @Test
    fun `verify key fingerprints for all bip39 test vectors`() {
        val tests = TestHelpers.readResourceAsJson("bip39_vectors.json")

        tests.jsonObject["english"]!!.jsonArray.forEach {
            val mnemonics = it.jsonArray[1].jsonPrimitive.content
            val seed = toSeed(mnemonics, "")
            val masterKey = DeterministicWallet.generate(seed)
            val fingerprint = masterKey.keyFingerprint()
            assertEquals(8, fingerprint.length)
        }
    }

    /**
     * Use this to reproduce the bug in [DeterministicWallet.ExtendedPublicKey.fingerprint]
     */
    @Test
    fun `fail verifying key fingerprints with negative fingerprint from bip39 test vectors`() {
        val tests = TestHelpers.readResourceAsJson("bip39_vectors.json")

        tests.jsonObject["english"]!!.jsonArray.forEach {
            val mnemonics = it.jsonArray[1].jsonPrimitive.content
            val seed = toSeed(mnemonics, "")
            val masterKey = DeterministicWallet.generate(seed)
            val fingerprint = masterKey.fingerprint().toString(16).padStart(8, '0')
            if (fingerprint.length == 8) return@forEach
            assertNotEquals(8, fingerprint.length)
        }
    }
}