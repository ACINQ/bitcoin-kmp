package fr.acinq.bitcoin

import kotlin.test.Test
import kotlin.test.assertEquals

class DescriptorTestsCommon {
    @Test
    fun `compute descriptor checksums`() {
        val data = listOf(
            "pkh([6ded4eb8/44h/0h/0h]xpub6C6N5WVF5zmurBR52MZZj8Jxm6eDiKyM4wFCm7xTYBEsAvJPqBKp2u2K7RTsZaYDN8duBWq4acrD4vrwjaKHTYuntGjL334nVHtLNuaj5Mu/0/*)#5mzpq0w6",
            "wpkh([6ded4eb8/84h/0h/0h]xpub6CDeom4xT3Wg7BuyXU2Sd9XerTKttyfxRwJE36mi5HxFYpYdtdwM76Zx8swPnc6zxuArMYJgjNy91fJ13YtGPHgf49YqA8KdXg6D69tzNFh/0/*)#refya6f0",
            "sh(wpkh([6ded4eb8/49h/0h/0h]xpub6Cb8jR9kYsfC6kj9CsE18SyudWjW2V3FnBFkT2oqq6n7NWWvJrjhFin3sAYg8X7ApX8iPophBa98mo4nMvSxnqrXvpnwaRopecQz859Ai1s/0/*))#xrhyhtvl",
            "tr([6ded4eb8/86h/0h/0h]xpub6CDp1iw76taes3pkqfiJ6PYhwURkaYksJ62CrrdTVr6ow9wR9mKAtUGoZQqb8pRDiq2F8k31tYrrJjVGTRSLYGQ7nYpmewH94ThsAgDxJ4h/0/*)#2nm7drky",
            "pkh([6ded4eb8/44h/0h/0h]xpub6C6N5WVF5zmurBR52MZZj8Jxm6eDiKyM4wFCm7xTYBEsAvJPqBKp2u2K7RTsZaYDN8duBWq4acrD4vrwjaKHTYuntGjL334nVHtLNuaj5Mu/1/*)#908qa67z",
            "wpkh([6ded4eb8/84h/0h/0h]xpub6CDeom4xT3Wg7BuyXU2Sd9XerTKttyfxRwJE36mi5HxFYpYdtdwM76Zx8swPnc6zxuArMYJgjNy91fJ13YtGPHgf49YqA8KdXg6D69tzNFh/1/*)#jdv9q0eh",
            "sh(wpkh([6ded4eb8/49h/0h/0h]xpub6Cb8jR9kYsfC6kj9CsE18SyudWjW2V3FnBFkT2oqq6n7NWWvJrjhFin3sAYg8X7ApX8iPophBa98mo4nMvSxnqrXvpnwaRopecQz859Ai1s/1/*))#nzej05eq",
            "tr([6ded4eb8/86h/0h/0h]xpub6CDp1iw76taes3pkqfiJ6PYhwURkaYksJ62CrrdTVr6ow9wR9mKAtUGoZQqb8pRDiq2F8k31tYrrJjVGTRSLYGQ7nYpmewH94ThsAgDxJ4h/1/*)#m87lskxu"
        )
        data.forEach { dnc ->
            val (desc, checksum) = dnc.split('#').toTypedArray()
            assertEquals(checksum, Descriptor.checksum(desc))
        }
    }

    @Test
    fun `compute BIP84 descriptors`() {
        val seed = ByteVector.fromHex("817a9c8e6ba36f083d7e68b5ee89ce74fde9ef294a724a5efc5cef2b88db057f")
        val master = DeterministicWallet.generate(seed)
        val descriptor = Descriptor.BIP84Descriptor(Block.RegtestGenesisBlock.hash, master)
        assertEquals("wpkh([189ef5fe/84'/1'/0'/0]tpubDFTu6FhLqfTBLMd7BvGkyH1h4XBw7XoKWfnNNWw5Sp8V6aC55EhgPTVNAYvBwBXQ8EGnMqaZi3dpdSzhMbD4Z7ivZiaVKNMUkXVjDU1CDuE/<0;1>/*)#rw8h72wu", descriptor)
    }
}