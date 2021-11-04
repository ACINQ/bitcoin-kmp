package fr.acinq.bitcoin

import kotlin.test.Test
import kotlin.test.assertEquals

class BIP86TestsCommon {
    @Test
    fun `BIP86 reference tests`() {
        val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "), "")
        val master = DeterministicWallet.generate(seed)
        assertEquals(DeterministicWallet.encode(master, DeterministicWallet.xprv), "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.xpub), "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8")

        val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/0'/0'"))
        assertEquals(DeterministicWallet.encode(accountKey, DeterministicWallet.xprv), "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.xpub), "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")

        val key = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 0L))
        assertEquals(key.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/0'/0'/0/0")).secretkeybytes)
        val internalKey = XonlyPublicKey(key.publicKey)
        assertEquals(internalKey.value, ByteVector32("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"))
        val outputKey = internalKey.outputKey
        assertEquals(outputKey.value, ByteVector32("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"))
        val script = listOf(OP_1, OP_PUSHDATA(outputKey.value))
        assertEquals(Script.write(script).byteVector(), ByteVector("5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"))

        val key1 = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 1L))
        assertEquals(key1.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/0'/0'/0/1")).secretkeybytes)
        val internalKey1 = XonlyPublicKey(key1.publicKey)
        assertEquals(internalKey1.value, ByteVector32("83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145"))
        val outputKey1 = internalKey1.outputKey
        assertEquals(outputKey1.value, ByteVector32("a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"))
        val script1 = listOf(OP_1, OP_PUSHDATA(outputKey1.value))
        assertEquals(Script.write(script1).byteVector(), ByteVector("5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"))

        val key2 = DeterministicWallet.derivePrivateKey(accountKey, listOf(1L, 0L))
        assertEquals(key2.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/86'/0'/0'/1/0")).secretkeybytes)
        val internalKey2 = XonlyPublicKey(key2.publicKey)
        assertEquals(internalKey2.value, ByteVector32("399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef"))
        val outputKey2 = internalKey2.outputKey
        assertEquals(outputKey2.value, ByteVector32("882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"))
        val script2 = listOf(OP_1, OP_PUSHDATA(outputKey2.value))
        assertEquals(Script.write(script2).byteVector(), ByteVector("5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"))
    }

    @Test
    fun `compute taproot addresses`() {
        val (_, master) = DeterministicWallet.ExtendedPrivateKey.decode("tprv8ZgxMBicQKsPeQQADibg4WF7mEasy3piWZUHyThAzJCPNgMHDVYhTCVfev3jFbDhcYm4GimeFMbbi9z1d9rfY1aL5wfJ9mNebQ4thJ62EJb")
        val key = DeterministicWallet.derivePrivateKey(master, "86'/1'/0'/0/1")
        val internalKey = XonlyPublicKey(key.publicKey)
        val outputKey = internalKey + PrivateKey(Crypto.taggedHash(internalKey.value.toByteArray(), "TapTweak")).publicKey()
        assertEquals("tb1phlhs7afhqzkgv0n537xs939s687826vn8l24ldkrckvwsnlj3d7qj6u57c", Bech32.encodeWitnessAddress("tb", 1, outputKey.value.toByteArray()))
    }
}