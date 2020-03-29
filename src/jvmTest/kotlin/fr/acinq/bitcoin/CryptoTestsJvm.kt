package fr.acinq.bitcoin

import kotlinx.serialization.InternalSerializationApi
import org.junit.Test
import kotlin.test.assertEquals

@ExperimentalUnsignedTypes
@ExperimentalStdlibApi
class CryptoTestsJvm {
    @Test
    fun `import private keys`() {
        // exported from the bitcoin client running in testnet mode
        val address = "mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY"
        val privateKey = "cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp"

        val (version, _) = Base58Check.decode(privateKey)
        assert(version == Base58.Prefix.SecretKeyTestnet)
        val priv = PrivateKey.fromBase58(privateKey, Base58.Prefix.SecretKeyTestnet).first
        val publicKey = priv.publicKey()
        val computedAddress = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, publicKey.hash160())
        assert(computedAddress == address)
    }

    @Test
    fun `generate public keys from private keys`() {
        val privateKey =
            PrivateKey(Hex.decode("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"))
        val publicKey = privateKey.publicKey()
        assert(publicKey.value == ByteVector("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"))
    }

    @Test
    fun `generate public keys from private keys 2`() {
        val privateKey =
            PrivateKey(Hex.decode("BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55"))
        val publicKey = privateKey.publicKey()
        assert(publicKey.value == ByteVector("03D7E9DD0C618C65DC2E3972E2AA406CCD34E5E77895C96DC48AF0CB16A1D9B8CE"))

        val address = Base58Check.encode(Base58.Prefix.PubkeyAddress, Crypto.hash160(publicKey.toUncompressedBin()))
        assert(address == "19FgFQGZy47NcGTJ4hfNdGMwS8EATqoa1X")
    }

    @Test
    fun `sign and verify signatures`() {
        val privateKey = PrivateKey.fromBase58(
            "cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp",
            Base58.Prefix.SecretKeyTestnet
        ).first
        val publicKey = privateKey.publicKey()
        val data = Crypto.sha256("this is a test".encodeToByteArray())
        val encoded = Crypto.sign(data, privateKey)
        assertEquals(ByteVector64("fb36b33afe9308f9eebfcdb0f50cb9c51c72e98a578ee26cabf4a26b5aba1fbf2429e5f5081488190fb01c5165189f2c70e619a3b667e6f1e0fc861d5a8a25d1"), encoded)
        assert(Crypto.verifySignature(data, encoded, publicKey))
    }

    @InternalSerializationApi
    @Test
    fun `der2compact`() {
        assertEquals(
            ByteVector64("3f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e78223ea13203caf853b71e97e5cc149f65547d1d7ab98c96353d0d8318934e7716"),
            Crypto.der2compact(Hex.decode("304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01"))
        )
    }
}