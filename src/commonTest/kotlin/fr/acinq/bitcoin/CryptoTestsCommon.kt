/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.bitcoin

import fr.acinq.bitcoin.reference.TransactionTestsCommon
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import org.kodein.memory.file.openReadableFile
import org.kodein.memory.file.resolve
import org.kodein.memory.io.readLine
import org.kodein.memory.use
import kotlin.random.Random
import kotlin.test.*

class CryptoTestsCommon {

    @Test
    fun `import private keys`() {
        // exported from the bitcoin client running in testnet mode
        val address = "mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY"
        val privateKey = "cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp"

        val (version, _) = Base58Check.decode(privateKey)
        assertEquals(Base58.Prefix.SecretKeyTestnet, version)
        val (priv, compressed) = PrivateKey.fromBase58(privateKey, Base58.Prefix.SecretKeyTestnet)
        assertTrue(compressed)
        assertEquals(priv.value, ByteVector32("7e39cf5faec688ce096d40726ec9322fb1f29ea7254f547dad788f9160753587"))
        assertContentEquals(priv.compress(), Hex.decode("7e39cf5faec688ce096d40726ec9322fb1f29ea7254f547dad788f916075358701"))
        val publicKey = priv.publicKey()
        val computedAddress = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, publicKey.hash160())
        assertEquals(address, computedAddress)
    }

    @Test
    fun `validate private keys`() {
        assertTrue(PrivateKey.fromHex("BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55").isValid())
        // Valid private keys must not be 0.
        assertFalse(PrivateKey.fromHex("0000000000000000000000000000000000000000000000000000000000000000").isValid())
        // Valid private keys must be strictly below the curve order.
        assertTrue(PrivateKey.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140").isValid())
        assertFalse(PrivateKey.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").isValid())
        assertFalse(PrivateKey.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").isValid())
    }

    @Test
    fun `check generator`() {
        val check = Secp256k1.pubkeyCreate(Hex.decode("0000000000000000000000000000000000000000000000000000000000000001"))
        assertEquals(PublicKey.Generator, PublicKey.parse(check))
    }

    @Test
    fun `generate public keys from private keys`() {
        val privateKey1 = PrivateKey.fromHex("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")
        val publicKey1 = privateKey1.publicKey()
        assertEquals(publicKey1.value, ByteVector("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"))

        val privateKey2 = PrivateKey.fromHex("BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55")
        val publicKey2 = privateKey2.publicKey()
        assertEquals(publicKey2.value, ByteVector("03D7E9DD0C618C65DC2E3972E2AA406CCD34E5E77895C96DC48AF0CB16A1D9B8CE"))

        val address = Base58Check.encode(Base58.Prefix.PubkeyAddress, Crypto.hash160(publicKey2.toUncompressedBin()))
        assertEquals(address, "19FgFQGZy47NcGTJ4hfNdGMwS8EATqoa1X")
    }

    @Test
    fun `compress and decompress public keys`() {
        val publicKey1 = PrivateKey.fromHex("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725").publicKey()
        assertTrue(Crypto.isPubKeyCompressedOrUncompressed(publicKey1.value.toByteArray()))
        assertTrue(Crypto.isPubKeyCompressed(publicKey1.value.toByteArray()))
        assertFalse(Crypto.isPubKeyUncompressed(publicKey1.value.toByteArray()))

        val uncompressed1 = publicKey1.toUncompressedBin()
        assertTrue(Crypto.isPubKeyCompressedOrUncompressed(uncompressed1))
        assertFalse(Crypto.isPubKeyCompressed(uncompressed1))
        assertTrue(Crypto.isPubKeyUncompressed(uncompressed1))

        val compressed1 = PublicKey.compress(uncompressed1)
        assertContentEquals(compressed1, publicKey1.value.toByteArray())
        assertTrue(Crypto.isPubKeyCompressedOrUncompressed(compressed1))
        assertTrue(Crypto.isPubKeyCompressed(compressed1))
        assertFalse(Crypto.isPubKeyUncompressed(compressed1))

        val publicKey2 = PublicKey(compressed1)
        assertTrue(Crypto.isPubKeyCompressedOrUncompressed(publicKey2.value.toByteArray()))
        assertTrue(Crypto.isPubKeyCompressed(publicKey2.value.toByteArray()))
        assertFalse(Crypto.isPubKeyUncompressed(publicKey2.value.toByteArray()))
        assertEquals(publicKey1.value, publicKey2.value)

        assertFails { PublicKey(uncompressed1) }
        val publicKey3 = PublicKey.parse(uncompressed1)
        assertTrue(Crypto.isPubKeyCompressedOrUncompressed(publicKey3.value.toByteArray()))
        assertTrue(Crypto.isPubKeyCompressed(publicKey3.value.toByteArray()))
        assertFalse(Crypto.isPubKeyUncompressed(publicKey3.value.toByteArray()))
        assertEquals(publicKey1.value, publicKey3.value)
    }

    @Test
    fun `create invalid public key`() {
        val privateKey = PrivateKey.fromHex("BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55")
        val publicKey = privateKey.publicKey()
        val nPublicKey = PublicKey.parse(Secp256k1.pubKeyNegate(publicKey.value.toByteArray()))
        // The result would be the point at infinity, which isn't a valid curve point.
        assertFails { publicKey - publicKey }
        assertFails { publicKey + nPublicKey }
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
        assertTrue(Crypto.verifySignature(data, encoded, publicKey))
    }

    @Test
    fun `der to compact`() {
        assertEquals(
            ByteVector64("3f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e78223ea13203caf853b71e97e5cc149f65547d1d7ab98c96353d0d8318934e7716"),
            Crypto.der2compact(Hex.decode("304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01"))
        )
    }

    @Test
    fun `generate deterministic signatures`() {
        val dataset = sequenceOf(
            Triple(
                "0000000000000000000000000000000000000000000000000000000000000001",
                "Satoshi Nakamoto",
                "3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
            ),
            Triple(
                "0000000000000000000000000000000000000000000000000000000000000001",
                "Everything should be made as simple as possible, but not simpler.",
                "3044022033a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c902206f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
            ),
            Triple(
                "0000000000000000000000000000000000000000000000000000000000000001",
                "All those moments will be lost in time, like tears in rain. Time to die...",
                "30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"
            ),
            Triple(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
                "Satoshi Nakamoto",
                "3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"
            ),
            Triple(
                "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
                "Alan Turing",
                "304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"
            ),
            Triple(
                "e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
                "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
                "3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6"
            )
        )
        dataset.forEach {
            val (k, m, s) = it
            val compact = Crypto.sign(Crypto.sha256(m.encodeToByteArray()), PrivateKey.fromHex(k))
            val sig = Crypto.compact2der(compact)

            assertEquals(Hex.encode(sig.toByteArray()), s)
        }
    }

    @Test
    fun `ECDH shared secrets`() {
        val privateKey = PrivateKey.fromHex("BCF69F7AFF3273B864F9DD76896FACE8E3D3CF69A133585C8177816F14FC9B55")
        val publicKey = privateKey.publicKey()
        val shared = Crypto.ecdh(privateKey, publicKey)
        assertEquals("56bc84cffc7db1ca04046fc04ec8f84232c340be789bc4779d221fe8b978af06", Hex.encode(shared))

        val random = Random
        val privateKey1 = PrivateKey(random.nextBytes(32))
        val privateKey2 = PrivateKey(random.nextBytes(32))
        val shared1 = Crypto.ecdh(privateKey1, privateKey2.publicKey())
        val shared2 = Crypto.ecdh(privateKey2, privateKey1.publicKey())
        assertContentEquals(shared1, shared2)
    }

    @Test
    fun `DER encoding compatibility tests`() {
        val sig = ByteVector64(ByteArray(64) { 0xaa.toByte() })
        val der = Crypto.compact2der(sig)
        assertEquals(der.size(), 71)
    }

    @Test
    fun `DER decoding compatibility tests`() {
        val der = Hex.decode("3045022100b50cbdd83b17b722b0e1f58e21cf3789ab18b36648023ed3811b522342ddaa9e02207182673961b7a10bfa94fe89780da0d03bfe1de137e0be32cc47a51edcaf08f301")
        val sig = Crypto.der2compact(der)
        assertEquals(sig, ByteVector64("b50cbdd83b17b722b0e1f58e21cf3789ab18b36648023ed3811b522342ddaa9e7182673961b7a10bfa94fe89780da0d03bfe1de137e0be32cc47a51edcaf08f3"))
    }

    @Test
    fun `recover public keys from signatures (random tests)`() {
        val random = Random
        val privbytes = ByteArray(32)
        val message = ByteArray(32)
        for (i in 1..100) {
            random.nextBytes(privbytes)
            random.nextBytes(message)

            val priv = PrivateKey(privbytes)
            val pub = priv.publicKey()
            val sig = Crypto.sign(message, priv)
            val (pub1, pub2) = Crypto.recoverPublicKey(sig, message)

            assertTrue(Crypto.verifySignature(message, sig, pub1))
            assertTrue(Crypto.verifySignature(message, sig, pub2))
            assertTrue(pub == pub1 || pub == pub2)
        }
    }

    @Test
    fun `recover public keys from signatures (secp256k1 test)`() {
        var priv: PrivateKey? = null
        var message: ByteVector? = null
        var pub: PublicKey? = null
        var sig: ByteVector? = null
        var recid: Int
        val file = TransactionTestsCommon.resourcesDir().resolve("recid.txt")
        file.openReadableFile().use {
            while (true) {
                val line = it.readLine() ?: return
                val values = line.split(" = ")
                val lhs = values[0]
                val rhs = values[1]
                when (lhs) {
                    "privkey" -> priv = PrivateKey(ByteVector(rhs).toByteArray())
                    "message" -> message = ByteVector(rhs)
                    "pubkey" -> pub = PublicKey(ByteVector(rhs))
                    "sig" -> sig = run {
                        val reversed = ByteVector(rhs).take(64)
                        ByteVector((reversed.take(32).reversed() + reversed.takeRight(32).reversed()).toByteArray())
                    }
                    "recid" -> {
                        recid = rhs.toInt()
                        assertEquals(priv!!.publicKey(), pub)
                        val sig1 = Crypto.sign(message!!.toByteArray(), priv!!)
                        assertEquals(sig1, sig)
                        val pub1 = Crypto.recoverPublicKey(sig1, message!!.toByteArray(), recid)
                        assertEquals(pub1, pub)
                    }
                }
            }
        }
    }

}