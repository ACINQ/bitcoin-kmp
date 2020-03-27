package fr.acinq.bitcoin.crypto

import fr.acinq.bitcoin.Hex
import kotlin.test.Test
import kotlin.test.assertTrue

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
class Sha1TestsCommon {
    val testVectors = arrayOf(
        "" to "da39a3ee5e6b4b0d3255bfef95601890afd80709" ,
        "abc" to "a9993e364706816aba3e25717850c26c9cd0d89d"//,
        //"a".repeat(1_000_000) to "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    )

    @Test
    fun `reference tests`() {
        testVectors.forEach { (input, expected) ->
            run {
                val digest = Sha1()
                val result = ByteArray(20)
                val bin = input.encodeToByteArray()
                digest.update(bin, 0, bin.size)
                digest.doFinal(result, 0)
                assertTrue { result.contentEquals(Hex.decode(expected)) }
            }
        }
    }
}