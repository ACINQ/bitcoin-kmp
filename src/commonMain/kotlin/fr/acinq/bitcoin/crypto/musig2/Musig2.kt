package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
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
    public fun tweak(tweak: ByteVector32, isXonly: Boolean): Pair<KeyAggCache, PublicKey> {
        val localCache = toByteArray()
        val tweaked = if (isXonly) {
            Secp256k1.musigPubkeyXonlyTweakAdd(localCache, tweak.toByteArray())
        } else {
            Secp256k1.musigPubkeyTweakAdd(localCache, tweak.toByteArray())
        }
        return Pair(KeyAggCache(localCache), PublicKey.parse(tweaked))
    }

    public companion object {
        /**
         * @param pubkeys public keys to aggregate
         * @param cache an optional key aggregation cache
         * @return a new (if cache was null) or updated cache, and the aggregated public key
         */
        @JvmStatic
        public fun add(pubkeys: List<PublicKey>, cache: KeyAggCache?): Pair<XonlyPublicKey, KeyAggCache> {
            val localCache = cache?.data?.toByteArray() ?: ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            val aggkey = Secp256k1.musigPubkeyAdd(pubkeys.map { it.value.toByteArray() }.toTypedArray(), localCache)
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
    public fun verify(psig: ByteVector32, pubnonce: IndividualNonce, pubkey: PublicKey, cache: KeyAggCache): Boolean {
        return Secp256k1.musigPartialSigVerify(psig.toByteArray(), pubnonce.toByteArray(), pubkey.value.toByteArray(), cache.data.toByteArray(), toByteArray()) == 1
    }

    /**
     * @param psigs partial signatures
     * @return the aggregate of all input partial signatures
     */
    public fun add(psigs: List<ByteVector32>): ByteVector64 {
        return Secp256k1.musigPartialSigAgg(toByteArray(), psigs.map { it.toByteArray() }.toTypedArray()).byteVector64()
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
            val session = Secp256k1.musigNonceProcess(aggregatedNonce.toByteArray(), msg.toByteArray(), cache.data.toByteArray(), null)
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
            return Pair(SecretNonce(nonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE)), IndividualNonce(nonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, Secp256k1.MUSIG2_SECRET_NONCE_SIZE + Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)))
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
        public fun aggregate(nonces: List<IndividualNonce>): AggregatedNonce {
            val agg = Secp256k1.musigNonceAgg(nonces.map { it.toByteArray() }.toTypedArray())
            return AggregatedNonce(agg)
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

public object Musig2 {
    /** Aggregate the public keys of a musig2 session into a single public key. */
    public fun aggregateKeys(publicKeys: List<PublicKey>): PublicKey = KeyAggCache.add(publicKeys, cache = null).first.publicKey

    /**
     * @param sessionId a random, unique session ID.
     * @param aggregatePublicKey aggregate public key of all participants of the musig2 session.
     */
    public fun generateNonce(sessionId: ByteVector32, privateKey: PrivateKey, aggregatePublicKey: PublicKey): SecretNonce = SecretNonce.generate(sessionId, privateKey, aggregatePublicKey, null, null, null).first

    /**
     * @param sessionId a random, unique session ID.
     * @param publicKeys public keys of all participants of the musig2 session.
     */
    public fun generateNonce(sessionId: ByteVector32, privateKey: PrivateKey, publicKeys: List<PublicKey>): SecretNonce = generateNonce(sessionId, privateKey, aggregateKeys(publicKeys))

    private fun taprootSession(tx: Transaction, inputIndex: Int, inputs: List<TxOut>, publicKeys: List<PublicKey>, publicNonces: List<IndividualNonce>, scriptTree: ScriptTree?): Session {
        val aggregatedNonce = IndividualNonce.aggregate(publicNonces)
        val (aggregatedKey, keyAggCache) = KeyAggCache.add(publicKeys, cache = null)
        val tweak = when (scriptTree) {
            null -> aggregatedKey.tweak(Crypto.TaprootTweak.NoScriptTweak)
            else -> aggregatedKey.tweak(Crypto.TaprootTweak.ScriptTweak(scriptTree))
        }
        val txHash = Transaction.hashForSigningTaprootKeyPath(tx, inputIndex, inputs, SigHash.SIGHASH_DEFAULT)
        return Session.build(aggregatedNonce, txHash, keyAggCache.tweak(tweak, isXonly = true).first)
    }

    /**
     * Create a partial musig2 signature for the given taproot input key path.
     *
     * @param privateKey private key of the signing participant.
     * @param tx transaction spending the target taproot input.
     * @param inputIndex index of the taproot input to spend.
     * @param inputs all inputs of the spending transaction.
     * @param publicKeys public keys of all participants of the musig2 session.
     * @param secretNonce secret nonce of the signing participant.
     * @param publicNonces public nonces of all participants of the musig2 session.
     * @param scriptTree tapscript tree of the taproot input, if it has script paths.
     */
    public fun signTaprootInput(privateKey: PrivateKey, tx: Transaction, inputIndex: Int, inputs: List<TxOut>, publicKeys: List<PublicKey>, secretNonce: SecretNonce, publicNonces: List<IndividualNonce>, scriptTree: ScriptTree?): ByteVector32? {
        val session = taprootSession(tx, inputIndex, inputs, publicKeys, publicNonces, scriptTree)
        return session.sign(secretNonce, privateKey, TODO()) // keyAggCache requirement is really weird
    }

    /**
     * Aggregate partial musig2 signatures into a valid schnorr signature for the given taproot input key path.
     *
     * @param partialSigs partial musig2 signatures of all participants of the musig2 session.
     * @param tx transaction spending the target taproot input.
     * @param inputIndex index of the taproot input to spend.
     * @param inputs all inputs of the spending transaction.
     * @param publicKeys public keys of all participants of the musig2 session.
     * @param publicNonces public nonces of all participants of the musig2 session.
     * @param scriptTree tapscript tree of the taproot input, if it has script paths.
     */
    @JvmStatic
    public fun aggregateTaprootSignatures(partialSigs: List<ByteVector32>, tx: Transaction, inputIndex: Int, inputs: List<TxOut>, publicKeys: List<PublicKey>, publicNonces: List<IndividualNonce>, scriptTree: ScriptTree?): ByteVector64 {
        val session = taprootSession(tx, inputIndex, inputs, publicKeys, publicNonces, scriptTree)
        // TODO: this may return errors on invalid partial sigs, it should be reflected in the types
        return session.add(partialSigs)
    }

}