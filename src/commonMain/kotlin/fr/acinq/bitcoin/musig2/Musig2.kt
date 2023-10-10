package fr.acinq.bitcoin.musig2

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.experimental.xor
import kotlin.jvm.JvmStatic


/**
 * Key Aggregation Context
 * Holds a public key aggregate that can optionally be tweaked
 * @param Q aggregated public key
 * @param gacc G accumulator
 * @param tacc tweak accumulator
 */
public data class KeyAggCtx(val Q: PublicKey, val gacc: Boolean, val tacc: ByteVector32) {
    public fun tweak(tweak: ByteVector32, isXonly: Boolean): KeyAggCtx {
        require(tweak == ByteVector32.Zeroes || PrivateKey(tweak).isValid()) { "invalid tweak" }
        return if (isXonly && !Q.isEven()) {
            val Q1 = PublicKey.parse(Secp256k1.pubKeyTweakAdd(Q.unaryMinus().toUncompressedBin(), tweak.toByteArray()))
            KeyAggCtx(Q1, !gacc, minus(tweak, tacc))
        } else {
            val Q1 = PublicKey.parse(Secp256k1.pubKeyTweakAdd(Q.toUncompressedBin(), tweak.toByteArray()))
            KeyAggCtx(Q1, gacc, add(tweak, tacc))
        }
    }
}

public object Musig2 {
    @JvmStatic
    public fun keyAgg(pubkeys: List<PublicKey>): KeyAggCtx {
        val pk2 = getSecondKey(pubkeys)
        val a = pubkeys.map { keyAggCoeffInternal(pubkeys, it, pk2) }
        val Q = pubkeys.zip(a).map { it.first.times(PrivateKey(it.second)) }.reduce { p1, p2 -> p1 + p2 }
        return KeyAggCtx(Q, true, ByteVector32.Zeroes)
    }

    @JvmStatic
    public fun keySort(pubkeys: List<PublicKey>): List<PublicKey> = pubkeys.sortedWith { a, b -> LexicographicalOrdering.compare(a, b) }
}
/**
 * Musig2 secret nonce. Not meant to be reused !!
 */
public data class SecretNonce(val p1: PrivateKey, val p2: PrivateKey, val pk: PublicKey) {
    public fun publicNonce(): PublicNonce = PublicNonce(p1.publicKey(), p2.publicKey())

    public companion object {
        @JvmStatic
        public fun fromValidHex(hex: String): SecretNonce {
            return fromBin(Hex.decode(hex))
        }

        @JvmStatic
        public fun fromBin(bin: ByteArray): SecretNonce {
            require(bin.size == 32 + 32 + 33)
            return SecretNonce(
                PrivateKey(bin.copyOfRange(0, 32)),
                PrivateKey(bin.copyOfRange(32, 64)),
                PublicKey(bin.copyOfRange(64, 97))
            )
        }

        /**
         * @param sk optional private key
         * @param pk public key
         * @param aggpk optional aggregated public key
         * @param msg optional message
         * @param extraInput optional extra input
         * @param randprime random value
         * @return a Musig2 secret nonce
         */
        @JvmStatic
        public fun generate(sk: PrivateKey?, pk: PublicKey, aggpk: XonlyPublicKey?, msg: ByteArray?, extraInput: ByteArray?, randprime: ByteVector32): SecretNonce {

            fun xor(a: ByteVector32, b: ByteVector32): ByteVector32 {
                val result = ByteArray(32)
                for (i in 0..31) {
                    result[i] = a[i].xor(b[i])
                }
                return result.byteVector32()
            }

            val rand = if (sk != null) {
                xor(sk.value, Crypto.taggedHash(randprime.toByteArray(), "MuSig/aux"))
            } else {
                randprime
            }
            val aggpk1 = aggpk?.value?.toByteArray() ?: ByteArray(0)
            val extraInput1 = extraInput ?: ByteArray(0)
            val tmp = rand.toByteArray() +
                    ByteArray(1) { pk.value.size().toByte() } + pk.value.toByteArray() +
                    ByteArray(1) { aggpk1.size.toByte() } + aggpk1 +
                    if (msg != null) {
                        ByteArray(1) { 1 } + Pack.writeInt64BE(msg.size.toLong()) + msg
                    } else {
                        ByteArray(1) { 0 }
                    } +
                    Pack.writeInt32BE(extraInput1.size) + extraInput1
            val k1 = Crypto.taggedHash(tmp + ByteArray(1) { 0 }, "MuSig/nonce")
            require(k1 != ByteVector32.Zeroes)
            val k2 = Crypto.taggedHash(tmp + ByteArray(1) { 1 }, "MuSig/nonce")
            require(k2 != ByteVector32.Zeroes)
            val secnonce = SecretNonce(PrivateKey(k1), PrivateKey(k2), pk)
            return secnonce
        }
    }
}

/**
 * Musig2 public nonce
 */
public data class PublicNonce(val P1: PublicKey?, val P2: PublicKey?) {
    public fun isValid(): Boolean = (P1?.isValid() ?: true) && (P2?.isValid() ?: true)

    public fun toByteArray(): ByteArray = (P1?.value?.toByteArray() ?: ByteArray(33)) + (P2?.value?.toByteArray() ?: ByteArray(33))

    public companion object {
        @JvmStatic
        public fun fromValidHex(hex: String): PublicNonce {
            return fromBin(Hex.decode(hex))
        }

        @JvmStatic
        public fun fromBin(bin: ByteArray): PublicNonce {
            require(bin.size == 33 + 33)
            val P1 = bin.copyOfRange(0, 33)
            val P2 = bin.copyOfRange(33, 66)
            return PublicNonce(if (P1.contentEquals(ByteArray(33))) null else PublicKey(P1), if (P2.contentEquals(ByteArray(33))) null else PublicKey(P2))
        }

        @JvmStatic
        public fun aggregate(nonces: List<PublicNonce>): PublicNonce {
            for (i in nonces.indices) {
                require(nonces[i].isValid()) { "invalid nonce at index $i" }
            }
            val R1 = nonces.map { it.P1 }.reduce { a, b -> add(a, b) }
            val R2 = nonces.map { it.P2 }.reduce { a, b -> add(a, b) }
            return PublicNonce(R1, R2)
        }
    }
}

internal fun add(a: ByteVector32, b: ByteVector32): ByteVector32 = when {
    a == ByteVector32.Zeroes -> b
    b == ByteVector32.Zeroes -> a
    else -> (PrivateKey(a) + PrivateKey(b)).value
}

internal fun unaryMinus(a: ByteVector32): ByteVector32 = when {
    a == ByteVector32.Zeroes -> a
    else -> PrivateKey(a).unaryMinus().value
}

internal fun minus(a: ByteVector32, b: ByteVector32): ByteVector32 = add(a, unaryMinus(b))
internal fun mul(a: ByteVector32, b: ByteVector32): ByteVector32 = when {
    a == ByteVector32.Zeroes || b == ByteVector32.Zeroes -> ByteVector32.Zeroes
    else -> (PrivateKey(a) * PrivateKey(b)).value
}

internal fun add(a: PublicKey?, b: PublicKey?): PublicKey? = when {
    a == null -> b
    b == null -> a
    a.xOnly() == b.xOnly() && (a.isEven() != b.isEven()) -> null
    else -> a + b
}


internal fun mul(a: PublicKey?, b: PrivateKey): PublicKey? = a?.times(b)

/**
 * Musig2 signing session context
 * @param aggnonce aggregated public nonce
 * @param pubkeys signer public keys
 * @param tweaks optional tweaks to apply to the aggregated public key
 * @param msg message to sign
 */
public data class SessionCtx(val aggnonce: PublicNonce, val pubkeys: List<PublicKey>, val tweaks: List<Pair<ByteVector32, Boolean>>, val message: ByteVector) {
    private fun build(): SessionValues {
        val keyAggCtx0 = Musig2.keyAgg(pubkeys)
        val keyAggCtx = tweaks.fold(keyAggCtx0) { ctx, tweak -> ctx.tweak(tweak.first, tweak.second) }
        val (Q, gacc, tacc) = keyAggCtx
        val b = PrivateKey(Crypto.taggedHash((aggnonce.toByteArray().byteVector() + Q.xOnly().value + message).toByteArray(), "MuSig/noncecoef"))
        val R = add(aggnonce.P1, mul(aggnonce.P2, b)) ?: PublicKey.Generator
        val e = Crypto.taggedHash((R.xOnly().value + Q.xOnly().value + message).toByteArray(), "BIP0340/challenge")
        return SessionValues(Q, gacc, tacc, b, R, PrivateKey(e))
    }

    private fun getSessionKeyAggCoeff(P: PublicKey): PrivateKey {
        require(pubkeys.contains(P)) { "signer's pubkey is not present" }
        return keyAggCoeff(pubkeys, P)
    }

    /**
     * @param secnonce secret nonce
     * @param sk private key
     * @return a Musig2 partial signature
     */
    public fun sign(secnonce: SecretNonce, sk: PrivateKey): ByteVector32 {
        val (Q, gacc, _, b, R, e) = build()
        val (k1, k2) = if (R.isEven()) Pair(secnonce.p1, secnonce.p2) else Pair(-secnonce.p1, -secnonce.p2)
        val P = sk.publicKey()
        require(P == secnonce.pk)
        val a = getSessionKeyAggCoeff(P)
        val d = if (Q.isEven() == gacc) sk else -sk
        val s = k1 + b * k2 + e * a * d
        require(partialSigVerify(s.value, secnonce.publicNonce(), sk.publicKey())) { "partial signature verification failed" }
        return s.value
    }

    /**
     * @param psig Musig2 partial signature
     * @param pubnonce public nonce
     * @param pk public key
     * @return true if the partial signature has been verified (in the context of a specific signing session)
     */
    public fun partialSigVerify(psig: ByteVector32, pubnonce: PublicNonce, pk: PublicKey): Boolean {
        val (Q, gacc, _, b, R, e) = build()
        val Rstar = add(pubnonce.P1, mul(pubnonce.P2, b)) ?: PublicKey.Generator
        val Re = if (R.isEven()) Rstar else -Rstar
        val a = getSessionKeyAggCoeff(pk)
        val gprime = if (Q.isEven()) gacc else !gacc
        val check = if (gprime) Re + pk * e * a else Re - pk * e * a
        return PrivateKey(psig).publicKey() == check
    }

    /**
     * @param psigs list of partial signatures
     * @return an aggregated signature, which is a valid Schnorr signature for the matching aggregated public key
     */
    public fun partialSigAgg(psigs: List<ByteVector32>): ByteVector64 {
        val (Q, _, tacc, _, R, e) = build()
        for (i in psigs.indices) {
            require(PrivateKey(psigs[i]).isValid()) { "invalid partial signature at index $i" }
        }
        val s = psigs.reduce { a, b -> add(a, b) }
        val s1 = if (Q.isEven()) add(s, mul(e.value, tacc)) else minus(s, mul(e.value, tacc))
        val sig = ByteVector64(R.xOnly().value + s1)
        return sig
    }

    public companion object {
        private data class SessionValues(val Q: PublicKey, val gacc: Boolean, val tacc: ByteVector32, val b: PrivateKey, val R: PublicKey, val e: PrivateKey)
    }
}

internal fun getSecondKey(pubkeys: List<PublicKey>): PublicKey {
    return pubkeys.drop(1).find { it != pubkeys[0] } ?: PublicKey(ByteArray(33))
}

internal fun hashKeys(pubkeys: List<PublicKey>): ByteVector32 {
    val concat = pubkeys.map { it.value }.reduce { a, b -> a + b }
    return Crypto.taggedHash(concat.toByteArray(), "KeyAgg list")
}

internal fun keyAggCoeffInternal(pubkeys: List<PublicKey>, pk: PublicKey, pk2: PublicKey): ByteVector32 {
    return if (pk == pk2) {
        ByteVector32.One.reversed()
    } else {
        Crypto.taggedHash(hashKeys(pubkeys).toByteArray() + pk.value.toByteArray(), "KeyAgg coefficient")
    }
}

internal fun keyAggCoeff(pubkeys: List<PublicKey>, pk: PublicKey): PrivateKey {
    return PrivateKey(keyAggCoeffInternal(pubkeys, pk, getSecondKey(pubkeys)))
}
