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
        val (accountDesc, changeDesc) = Descriptor.BIP84Descriptors(Block.RegtestGenesisBlock.hash, master)
        assertEquals("wpkh([189ef5fe/84'/1'/0']tpubDDsHdjGe26Kqr5QgesP2HFS7UTJs3uS39Lq66m4AytUmxM1sbe7qppMohp7awxBRAVdriHRUAoBZvfwpyqAhPHKPqmME82jZJ8zfVaHuVi1/0/*)#4eqzu535", accountDesc)
        assertEquals("wpkh([189ef5fe/84'/1'/0']tpubDDsHdjGe26Kqr5QgesP2HFS7UTJs3uS39Lq66m4AytUmxM1sbe7qppMohp7awxBRAVdriHRUAoBZvfwpyqAhPHKPqmME82jZJ8zfVaHuVi1/1/*)#yd9rpppv", changeDesc)
        assertEquals(Pair(accountDesc, changeDesc), Descriptor.BIP84Descriptors(Block.SignetGenesisBlock.hash, master))
    }

    @Test
    fun `compute BIP84 descriptors -- reference test vector`() {
        // https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors
        val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
        val master = DeterministicWallet.generate(seed)
        val (_, accountPub) = DeterministicWallet.ExtendedPublicKey.decode("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
        assertEquals(accountPub.publicKey, master.derivePrivateKey(KeyPath("m/84'/0'/0'")).publicKey)
        val (accountDesc, changeDesc) = Descriptor.BIP84Descriptors(Block.LivenetGenesisBlock.hash, master)
        assertEquals("wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#wc3n3van", accountDesc)
        assertEquals("wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/1/*)#lv5jvedt", changeDesc)
        assertEquals(Pair(accountDesc, changeDesc), Descriptor.BIP84Descriptors(Block.LivenetGenesisBlock.hash, master.fingerprint(), accountPub))

        // Fingerprints are always encoded on 8 hex characters, including leading zeroes.
        val (paddedDesc, _) = Descriptor.BIP84Descriptors(Block.LivenetGenesisBlock.hash, 0x0a1b2c3dL, accountPub)
        assertEquals("wpkh([0a1b2c3d/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#hr5fztyr", paddedDesc)
    }

}