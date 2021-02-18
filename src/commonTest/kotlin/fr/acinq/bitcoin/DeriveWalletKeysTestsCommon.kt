package fr.acinq.bitcoin

import kotlin.test.Test
import kotlin.test.assertEquals

class DeriveWalletKeysTestsCommon {
    val mnemonics = "gun please vital unable phone catalog explain raise erosion zoo truly exist"
    val seed = MnemonicCode.toSeed(mnemonics, "")
    val master = DeterministicWallet.generate(seed)

    @Test
    fun `restore BIP44 wallet`() {
        val account = DeterministicWallet.derivePrivateKey(master, KeyPath("m/44'/1'/0'"))
        // some wallets will use tpub instead of upub
        val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.tpub)
        assertEquals(xpub, "tpubDDamug2qVwe94yFJ38MM3ek2LiWiyjMmkQPhYMnHNZz5XHj7bj8xc7pFmyiYnCfqrSy62e1196qcpmKYhcUMcBTGMW4mEWf1v9H8wNtLZku")
        assertEquals(
            deriveAddresses(xpub, DerivationScheme.BIP44),
            listOf("mmpDgTP9FQbJCcdkkuXLbjbvqg3j33Zw3H", "mtXgQHM7Eawr6rjDWh7CrFtBQnbibviekL", "mw39H2JNixLuXLfTXqZr53M1n18ekPNi9U", "mnK3W3DMnkKMPT3Kbx6gvrmWxch6BhNHoo", "mpotVZLVr3fgbuBD2jzmwxVg7iATpq7YME")
        )
    }

    @Test
    fun `restore BIP49 wallet`() {
        val account = DeterministicWallet.derivePrivateKey(master, KeyPath("m/49'/1'/0'"))
        // some wallets will use tpub instead of upub
        val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.upub)
        assertEquals(xpub, "upub5DKk7kdrLoL3HqrfVdf3mLZJ59g6Bix8UtB6YJQNSKfE3E6YU2Vq7dH7E8ce87jUAac4nRag6Zd7c2cXs45Q4nJcLdrJyNWPxS5D9LFSpGL")
        assertEquals(
            deriveAddresses(xpub),
            listOf(
                "2NAV38YdZBS6s6b89QdmyPnjBxn6Jn3BkhQ",
                "2Mzxym6Rey5Mwnnxh6L134MaHFwTPQB4fdx",
                "2N8tTGMc57REfePZzPkWqEGaYKHsrVsW3LJ",
                "2Mxfuivcx4TdGroh6Q2GmCR5rQB46fjJUtn",
                "2N7uWEqMPCjzHynqSDaAnydZD6WfEpH9ekz"
            )
        )
    }

    @Test
    fun `restore BIP84 wallet`() {
        val account = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/1'/0'"))
        // some wallets will use tpub instead of upub
        val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.vpub)
        assertEquals(xpub, "vpub5YmxxDXhaEfLoqxn8xJExGMSQepxRbJDFqyc9FpDKyW8z966eDsgqbTHnJCvc698MhN3FDRt49DuPBgdRufopecaeyffJCUKXRKHoNn7BhX")
        assertEquals(
            deriveAddresses(xpub),
            listOf(
                "tb1ql63el50rtln6n4kxa76jrhuts3kxmk9wtz6hp0",
                "tb1qa2hyhca4y07xqcl9r9m63rtv4hgdh063hldn6r",
                "tb1q0lywyl3cdkuw29yuh6w0frqh4hnxdj0m4e78eq",
                "tb1q4dg72vn06mrjh3yyzpkws3w2z0whrys8g2a997",
                "tb1qx4g3glhflr42clkkla9ty0vmfcmme9a426mrc2"
            )
        )
    }

    companion object {
        sealed class DerivationScheme {
            object BIP44 : DerivationScheme()
            object BIP49 : DerivationScheme()
            object BIP84 : DerivationScheme()
        }

        fun deriveAddresses(xpub: String, derivationScheme: DerivationScheme? = null): List<String> {
            val (prefix, master) = DeterministicWallet.ExtendedPublicKey.decode(xpub)
            return (0L..4L).map {
                val pub = DeterministicWallet.derivePublicKey(master, listOf(0L, it))
                val address = when {
                    prefix == DeterministicWallet.tpub && derivationScheme == DerivationScheme.BIP44 -> computeBIP44Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
                    prefix == DeterministicWallet.tpub && derivationScheme == DerivationScheme.BIP49 -> computeBIP49Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
                    prefix == DeterministicWallet.upub -> computeBIP49Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
                    prefix == DeterministicWallet.vpub -> computeBIP84Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
                    prefix == DeterministicWallet.xpub && derivationScheme == DerivationScheme.BIP44 -> computeBIP44Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
                    prefix == DeterministicWallet.xpub && derivationScheme == DerivationScheme.BIP49 -> computeBIP49Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
                    prefix == DeterministicWallet.ypub -> computeBIP49Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
                    prefix == DeterministicWallet.zpub -> computeBIP84Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
                    else -> error("invalid prefix $prefix")
                }
                address
            }
        }
    }
}