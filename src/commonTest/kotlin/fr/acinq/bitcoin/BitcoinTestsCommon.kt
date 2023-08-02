package fr.acinq.bitcoin

import fr.acinq.bitcoin.Bitcoin.addressFromPublicKeyScript
import fr.acinq.bitcoin.Bitcoin.addressToPublicKeyScript
import fr.acinq.bitcoin.Bitcoin.computeP2PkhAddress
import fr.acinq.bitcoin.Bitcoin.computeP2ShOfP2WpkhAddress
import fr.acinq.bitcoin.Bitcoin.computeP2WpkhAddress
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class BitcoinTestsCommon {
    @Test
    fun `update lists`() {
        assertEquals(listOf<Int>().updated(0, 1), listOf(1))
        assertEquals(listOf(5).updated(0, 1), listOf(1))
        val l = listOf(2, 3, 5, 7, 11, 13, 17)
        assertFails { l.updated(-1, 1) }
        assertEquals(l.updated(0, 1), listOf(1, 3, 5, 7, 11, 13, 17))
        assertEquals(l.updated(1, 1), listOf(2, 1, 5, 7, 11, 13, 17))
        assertEquals(l.updated(2, 1), listOf(2, 3, 1, 7, 11, 13, 17))
        assertEquals(l.updated(3, 1), listOf(2, 3, 5, 1, 11, 13, 17))
        assertEquals(l.updated(4, 1), listOf(2, 3, 5, 7, 1, 13, 17))
        assertEquals(l.updated(5, 1), listOf(2, 3, 5, 7, 11, 1, 17))
        assertEquals(l.updated(6, 1), listOf(2, 3, 5, 7, 11, 13, 1))
        assertEquals(l.updated(7, 1), listOf(2, 3, 5, 7, 11, 13, 17, 1))
        assertEquals(l.updated(42, 1), listOf(2, 3, 5, 7, 11, 13, 17, 1))
    }

    @Test
    fun `compute address from pubkey script`() {
        val pub = PrivateKey.fromHex("0101010101010101010101010101010101010101010101010101010101010101").publicKey()

        fun address(script: List<ScriptElt>, chainHash: ByteVector32) = addressFromPublicKeyScript(chainHash, script)

        listOf(Block.LivenetGenesisBlock.hash, Block.TestnetGenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash).forEach {
            assertEquals(address(Script.pay2pkh(pub), it).result, computeP2PkhAddress(pub, it))
            assertEquals(address(Script.pay2wpkh(pub), it).result, computeP2WpkhAddress(pub, it))
            assertEquals(address(Script.pay2sh(Script.pay2wpkh(pub)), it).result, computeP2ShOfP2WpkhAddress(pub, it))
            // all these chain hashes are invalid
            assertTrue(address(Script.pay2pkh(pub), it.reversed()).isFailure())
            assertTrue(address(Script.pay2wpkh(pub), it.reversed()).isFailure())
            assertTrue(address(Script.pay2sh(Script.pay2wpkh(pub)), it.reversed()).isFailure())
        }

        listOf(
            Triple("0014d0b19277b0f76c9512f26d77573fd31a8fd15fc7", Block.TestnetGenesisBlock.hash, "tb1q6zceyaas7akf2yhjd4m4w07nr28azh78gw79kk"),
            Triple("00203287047df2aa7aade3f394790a9c9d6f9235943f48a012e8a9f2c3300ca4f2d1", Block.TestnetGenesisBlock.hash, "tb1qx2rsgl0j4fa2mclnj3us48yad7frt9plfzsp969f7tpnqr9y7tgsyprxej"),
            Triple("76a914b17deefe2feab87fef7221cf806bb8ca61f00fa188ac", Block.TestnetGenesisBlock.hash, "mwhSm2SHhRhd19KZyaQLgJyAtCLnkbzWbf"),
            Triple("a914d3cf9d04f4ecc36df8207b300e46bc6775fc84c087", Block.TestnetGenesisBlock.hash, "2NCZBGzKadAnLv1ijAqhrKavMuqvxqu18yY"),
            Triple("00145cb882efd643b7d63ae133e4d5e88e10bd5a20d7", Block.LivenetGenesisBlock.hash, "bc1qtjug9m7kgwmavwhpx0jdt6ywzz745gxhxwyn8u"),
            Triple("00208c2865c87ffd33fc5d698c7df9cf2d0fb39d93103c637a06dea32c848ebc3e1d", Block.LivenetGenesisBlock.hash, "bc1q3s5xtjrll5elchtf337lnnedp7eemycs833h5pk75vkgfr4u8cws3ytg02"),
            Triple("76a914536ffa992491508dca0354e52f32a3a7a679a53a88ac", Block.LivenetGenesisBlock.hash, "18cBEMRxXHqzWWCxZNtU91F5sbUNKhL5PX"),
            Triple("a91481b9ac6a59b53927da7277b5ad5460d781b365d987", Block.LivenetGenesisBlock.hash, "3DWwX7NYjnav66qygrm4mBCpiByjammaWy"),
        ).forEach {
            assertEquals(addressFromPublicKeyScript(it.second, Hex.decode(it.first)).result, it.third)
        }
    }

    @Test
    fun `decode base58 addresses`() {
        val pub = PrivateKey.fromHex("0101010101010101010101010101010101010101010101010101010101010101").publicKey()

        // p2pkh
        // valid chain
        assertEquals(addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, pub.hash160())), AddressToPublicKeyScriptResult.Success(Script.pay2pkh(pub)))
        assertEquals(addressToPublicKeyScript(Block.RegtestGenesisBlock.hash, Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, pub.hash160())), AddressToPublicKeyScriptResult.Success((Script.pay2pkh(pub))))
        assertEquals(addressToPublicKeyScript(Block.SignetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, pub.hash160())), AddressToPublicKeyScriptResult.Success(Script.pay2pkh(pub)))
        assertEquals(addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.PubkeyAddress, pub.hash160())), AddressToPublicKeyScriptResult.Success(Script.pay2pkh(pub)))

        // wrong chain
        assertEquals(addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.PubkeyAddress, pub.hash160())), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.PubkeyAddress, pub.hash160())), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.SignetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.PubkeyAddress, pub.hash160())), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.RegtestGenesisBlock.hash, Base58Check.encode(Base58.Prefix.PubkeyAddress, pub.hash160())), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)

        // p2sh
        val script = Script.write(Script.pay2wpkh(pub))

        // valid chain
        assertEquals(addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, Crypto.hash160(script))), AddressToPublicKeyScriptResult.Success(Script.pay2sh(script)))
        assertEquals(addressToPublicKeyScript(Block.RegtestGenesisBlock.hash, Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, Crypto.hash160(script))), AddressToPublicKeyScriptResult.Success(Script.pay2sh(script)))
        assertEquals(addressToPublicKeyScript(Block.SignetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, Crypto.hash160(script))), AddressToPublicKeyScriptResult.Success(Script.pay2sh(script)))
        assertEquals(addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.ScriptAddress, Crypto.hash160(script))), AddressToPublicKeyScriptResult.Success(Script.pay2sh(script)))

        // wrong chain
        assertEquals(addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, Crypto.hash160(script))), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.ScriptAddress, Crypto.hash160(script))), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.RegtestGenesisBlock.hash, Base58Check.encode(Base58.Prefix.ScriptAddress, Crypto.hash160(script))), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.SignetGenesisBlock.hash, Base58Check.encode(Base58.Prefix.ScriptAddress, Crypto.hash160(script))), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
    }

    @Test
    fun `decode bech32 addresses`() {
        val pub = PrivateKey.fromHex("0101010101010101010101010101010101010101010101010101010101010101").publicKey()

        // p2wpkh
        assertEquals(addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, Bech32.encodeWitnessAddress("bc", 0, pub.hash160())), AddressToPublicKeyScriptResult.Success(Script.pay2wpkh(pub)))
        assertEquals(addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, Bech32.encodeWitnessAddress("tb", 0, pub.hash160())), AddressToPublicKeyScriptResult.Success(Script.pay2wpkh(pub)))
        assertEquals(addressToPublicKeyScript(Block.SignetGenesisBlock.hash, Bech32.encodeWitnessAddress("tb", 0, pub.hash160())), AddressToPublicKeyScriptResult.Success(Script.pay2wpkh(pub)))
        assertEquals(addressToPublicKeyScript(Block.RegtestGenesisBlock.hash, Bech32.encodeWitnessAddress("bcrt", 0, pub.hash160())), AddressToPublicKeyScriptResult.Success(Script.pay2wpkh(pub)))

        // wrong chain
        assertEquals(addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, Bech32.encodeWitnessAddress("bc", 0, pub.hash160())), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.SignetGenesisBlock.hash, Bech32.encodeWitnessAddress("bc", 0, pub.hash160())), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, Bech32.encodeWitnessAddress("tb", 0, pub.hash160())), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)
        assertEquals(addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, Bech32.encodeWitnessAddress("bcrt", 0, pub.hash160())), AddressToPublicKeyScriptResult.Failure.ChainHashMismatch)

        val script = Script.write(Script.pay2wpkh(pub))
        assertEquals(addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, Bech32.encodeWitnessAddress("bc", 0, Crypto.sha256(script))), AddressToPublicKeyScriptResult.Success(Script.pay2wsh(script)))
        assertEquals(addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, Bech32.encodeWitnessAddress("tb", 0, Crypto.sha256(script))), AddressToPublicKeyScriptResult.Success(Script.pay2wsh(script)))
        assertEquals(addressToPublicKeyScript(Block.SignetGenesisBlock.hash, Bech32.encodeWitnessAddress("tb", 0, Crypto.sha256(script))), AddressToPublicKeyScriptResult.Success(Script.pay2wsh(script)))
        assertEquals(addressToPublicKeyScript(Block.RegtestGenesisBlock.hash, Bech32.encodeWitnessAddress("bcrt", 0, Crypto.sha256(script))), AddressToPublicKeyScriptResult.Success(Script.pay2wsh(script)))
    }

    @Test
    fun `check genesis block hashes`() {
        assertEquals(Block.RegtestGenesisBlock.blockId, ByteVector32.fromValidHex("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
        assertEquals(Block.SignetGenesisBlock.blockId, ByteVector32.fromValidHex("0x00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"))
        assertEquals(Block.TestnetGenesisBlock.blockId, ByteVector32.fromValidHex("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"))
        assertEquals(Block.LivenetGenesisBlock.blockId, ByteVector32.fromValidHex("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"))
    }
}