package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

/**
 * Musig2 key aggregation cache
 * Keeps track of an aggregate of public keys, that can optionally be tweaked
 */
public data class KeyAggCache(val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        require(data.size() == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "musig2 keyagg cache must be ${Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    /**
     * @param tweak tweak to apply
     * @param isXonly true if the tweak is an x-only tweak
     * @return an updated cache, and the tweaked aggregated public key
     */
    public fun tweak(tweak: ByteVector32, isXonly: Boolean): Either<Throwable, Pair<KeyAggCache, PublicKey>> = try {
        val localCache = toByteArray()
        val tweaked = if (isXonly) {
            Secp256k1.musigPubkeyXonlyTweakAdd(localCache, tweak.toByteArray())
        } else {
            Secp256k1.musigPubkeyTweakAdd(localCache, tweak.toByteArray())
        }
        Either.Right(Pair(KeyAggCache(localCache), PublicKey.parse(tweaked)))
    } catch (t: Throwable) {
        Either.Left(t)
    }

    public companion object {
        /**
         * @param pubkeys public keys to aggregate
         * @param cache an optional key aggregation cache
         * @return a new (if cache was null) or updated cache, and the aggregated public key
         */
        @JvmStatic
        @JvmOverloads
        public fun add(pubkeys: List<PublicKey>, cache: KeyAggCache? = null): Pair<XonlyPublicKey, KeyAggCache> {
            val localCache = cache?.data?.toByteArray() ?: ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            val aggkey = Secp256k1.musigPubkeyAgg(pubkeys.map { it.value.toByteArray() }.toTypedArray(), localCache)
            return Pair(XonlyPublicKey(aggkey.byteVector32()), KeyAggCache(localCache.byteVector()))
        }
    }
}

/**
 * Musig2 signing session
 */
public data class Session(val data: ByteVector) {
    init {
        require(data.size() == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "musig2 session must be ${Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    /**
     * @param secretNonce secret nonce
     * @param pk private key
     * @param aggCache key aggregation cache
     * @return a Musig2 partial signature
     */
    public fun sign(secretNonce: SecretNonce, pk: PrivateKey, aggCache: KeyAggCache): ByteVector32 {
        return Secp256k1.musigPartialSign(secretNonce.data.toByteArray(), pk.value.toByteArray(), aggCache.data.toByteArray(), toByteArray()).byteVector32()
    }

    /**
     * @param psig musig2 partial signature
     * @param pubnonce public nonce, that must match the secret nonce psig was generated with
     * @param pubkey public key, that must match the private key psig was generated with
     * @param cache key aggregation cache
     * @return true if the partial signature is valid
     */
    public fun verify(psig: ByteVector32, pubnonce: IndividualNonce, pubkey: PublicKey, cache: KeyAggCache): Boolean = try {
        Secp256k1.musigPartialSigVerify(psig.toByteArray(), pubnonce.toByteArray(), pubkey.value.toByteArray(), cache.data.toByteArray(), toByteArray()) == 1
    } catch (t: Throwable) {
        false
    }

    /**
     * @param psigs partial signatures
     * @return the aggregate of all input partial signatures
     */
    public fun add(psigs: List<ByteVector32>): Either<Throwable, ByteVector64> = try {
        Either.Right(Secp256k1.musigPartialSigAgg(toByteArray(), psigs.map { it.toByteArray() }.toTypedArray()).byteVector64())
    } catch (t: Throwable) {
        Either.Left(t)
    }


    public companion object {
        /**
         * @param aggregatedNonce aggregated public nonce
         * @param msg message to sign
         * @param cache key aggregation cache
         * @return a Musig signing session
         */
        @JvmStatic
        public fun build(aggregatedNonce: AggregatedNonce, msg: ByteVector32, cache: KeyAggCache): Session {
            val session = Secp256k1.musigNonceProcess(aggregatedNonce.toByteArray(), msg.toByteArray(), cache.data.toByteArray())
            return Session(session.byteVector())
        }
    }
}

/**
 * Musig2 secret nonce. Not meant to be reused !!
 */
public data class SecretNonce(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())

    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.MUSIG2_SECRET_NONCE_SIZE) { "musig2 secret nonce must be ${Secp256k1.MUSIG2_SECRET_NONCE_SIZE} bytes" }
    }

    public companion object {
        /**
         * @param sessionId random session id. Must not be reused !!
         * @param seckey optional private key
         * @param pubkey public key
         * @param msg optional message to sign
         * @param cache optional key aggregation cache
         * @param extraInput optional extra input value
         * @return a (secret nonce, public nonce) tuple
         */
        @JvmStatic
        public fun generate(sessionId: ByteVector32, seckey: PrivateKey?, pubkey: PublicKey, msg: ByteVector32?, cache: KeyAggCache?, extraInput: ByteVector32?): Pair<SecretNonce, IndividualNonce> {
            val nonce = Secp256k1.musigNonceGen(sessionId.toByteArray(), seckey?.value?.toByteArray(), pubkey.value.toByteArray(), msg?.toByteArray(), cache?.data?.toByteArray(), extraInput?.toByteArray())
            val secretNonce = SecretNonce(nonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE))
            val publicNonce = IndividualNonce(nonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, Secp256k1.MUSIG2_SECRET_NONCE_SIZE + Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE))
            return Pair(secretNonce, publicNonce)
        }
    }
}

/**
 * Musig2 public nonce
 */
public data class IndividualNonce(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())

    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "individual musig2 public nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    public companion object {
        @JvmStatic
        public fun aggregate(nonces: List<IndividualNonce>): Either<Throwable, AggregatedNonce> = try {
            val agg = Secp256k1.musigNonceAgg(nonces.map { it.toByteArray() }.toTypedArray())
            Either.Right(AggregatedNonce(agg))
        } catch (t: Throwable) {
            Either.Left(t)
        }
    }
}

/**
 * Musig2 aggregated nonce
 */
public data class AggregatedNonce(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())

    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "aggregated musig2 public nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()
}