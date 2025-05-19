package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.flatMap
import fr.acinq.bitcoin.utils.getOrElse
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

/**
 * Musig2 key aggregation cache: keeps track of an aggregate of public keys, that can optionally be tweaked.
 * This should be treated as an opaque blob of data, that doesn't contain any sensitive data and thus can be stored.
 */
public data class KeyAggCache(private val data: ByteVector) {
    public constructor(data: ByteArray) : this(data.byteVector())

    init {
        require(data.size() == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE) { "musig2 keyagg cache must be ${Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()

    /**
     * @param tweak tweak to apply.
     * @param isXonly true if the tweak is an x-only tweak.
     * @return an updated cache and the tweaked aggregated public key, or null if one of the tweaks is invalid.
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
         * @param publicKeys public keys to aggregate: callers must verify that all public keys are valid.
         * @return an opaque key aggregation cache and the aggregated public key.
         */
        @JvmStatic
        public fun create(publicKeys: List<PublicKey>): Pair<XonlyPublicKey, KeyAggCache> {
            require(publicKeys.all { it.isValid() }) { "some of the public keys provided are not valid" }
            val localCache = ByteArray(Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            val aggkey = Secp256k1.musigPubkeyAgg(publicKeys.map { it.value.toByteArray() }.toTypedArray(), localCache)
            return Pair(XonlyPublicKey(aggkey.byteVector32()), KeyAggCache(localCache.byteVector()))
        }
    }
}

/**
 * Musig2 signing session context that can be used to create partial signatures and aggregate them.
 */
public data class Session(private val data: ByteVector, private val keyAggCache: KeyAggCache) {
    init {
        require(data.size() == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE) { "musig2 session must be ${Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    /**
     * @param secretNonce signer's secret nonce (see [SecretNonce.generate]).
     * @param privateKey signer's private key.
     * @return a musig2 partial signature.
     */
    public fun sign(secretNonce: SecretNonce, privateKey: PrivateKey): ByteVector32 {
        return Secp256k1.musigPartialSign(secretNonce.data.toByteArray(), privateKey.value.toByteArray(), keyAggCache.toByteArray(), this.toByteArray()).byteVector32()
    }

    /**
     * @param partialSig musig2 partial signature.
     * @param publicNonce individual public nonce of the signing participant.
     * @param publicKey individual public key of the signing participant.
     * @return true if the partial signature is valid.
     */
    public fun verify(partialSig: ByteVector32, publicNonce: IndividualNonce, publicKey: PublicKey): Boolean = try {
        Secp256k1.musigPartialSigVerify(partialSig.toByteArray(), publicNonce.toByteArray(), publicKey.value.toByteArray(), keyAggCache.toByteArray(), this.toByteArray()) == 1
    } catch (t: Throwable) {
        false
    }

    /**
     * Aggregate partial signatures from all participants into a single schnorr signature. Callers should verify the
     * resulting signature, which may be invalid without raising an error here (for example if the set of partial
     * signatures is valid but incomplete).
     *
     * @param partialSigs partial signatures from all signing participants.
     * @return the aggregate signature of all input partial signatures or null if a partial signature is invalid.
     */
    public fun aggregateSigs(partialSigs: List<ByteVector32>): Either<Throwable, ByteVector64> = try {
        Either.Right(Secp256k1.musigPartialSigAgg(this.toByteArray(), partialSigs.map { it.toByteArray() }.toTypedArray()).byteVector64())
    } catch (t: Throwable) {
        Either.Left(t)
    }

    public companion object {
        /**
         * @param aggregatedNonce aggregated public nonce.
         * @param message message that will be signed.
         * @param keyAggCache key aggregation cache.
         * @return a musig2 signing session.
         */
        @JvmStatic
        public fun create(aggregatedNonce: AggregatedNonce, message: ByteVector32, keyAggCache: KeyAggCache): Session {
            val session = Secp256k1.musigNonceProcess(aggregatedNonce.toByteArray(), message.toByteArray(), keyAggCache.toByteArray())
            return Session(session.byteVector(), keyAggCache)
        }
    }
}

/**
 * Musig2 secret nonce, that should be treated as a private opaque blob.
 * This nonce must never be persisted or reused across signing sessions.
 */
public data class SecretNonce(internal val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())
    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.MUSIG2_SECRET_NONCE_SIZE) { "musig2 secret nonce must be ${Secp256k1.MUSIG2_SECRET_NONCE_SIZE} bytes" }
    }

    override fun toString(): String = "<secret_nonce>"

    public companion object {
        /**
         * Generate a secret nonce to be used in a musig2 signing session.
         * This nonce must never be persisted or reused across signing sessions.
         * All optional arguments exist to enrich the quality of the randomness used, which is critical for security.
         *
         * @param sessionId unique session ID.
         * @param privateKey (optional) signer's private key.
         * @param publicKey signer's public key.
         * @param message (optional) message that will be signed, if already known.
         * @param keyAggCache (optional) key aggregation cache data from the signing session.
         * @param extraInput (optional) additional random data.
         * @return secret nonce and the corresponding public nonce.
         */
        @JvmStatic
        public fun generate(sessionId: ByteVector32, privateKey: PrivateKey?, publicKey: PublicKey, message: ByteVector32?, keyAggCache: KeyAggCache?, extraInput: ByteVector32?): Pair<SecretNonce, IndividualNonce> {
            privateKey?.let { require(it.publicKey() == publicKey) { "if the private key is provided, it must match the public key" } }
            val nonce = Secp256k1.musigNonceGen(sessionId.toByteArray(), privateKey?.value?.toByteArray(), publicKey.value.toByteArray(), message?.toByteArray(), keyAggCache?.toByteArray(), extraInput?.toByteArray())
            val secretNonce = SecretNonce(nonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE))
            val publicNonce = IndividualNonce(nonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, Secp256k1.MUSIG2_SECRET_NONCE_SIZE + Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE))
            return Pair(secretNonce, publicNonce)
        }
    }
}

/**
 * Musig2 public nonce, that must be shared with other participants in the signing session.
 * It contains two elliptic curve points, but should be treated as an opaque blob.
 */
public data class IndividualNonce(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())
    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "individual musig2 public nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()

    public companion object {
        /**
         * Aggregate public nonces from all participants of a signing session.
         * Returns null if one of the nonces provided is invalid.
         */
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
 * Musig2 aggregate public nonce from all participants of a signing session.
 */
public data class AggregatedNonce(val data: ByteVector) {
    public constructor(bin: ByteArray) : this(bin.byteVector())
    public constructor(hex: String) : this(Hex.decode(hex))

    init {
        require(data.size() == Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE) { "aggregated musig2 public nonce must be ${Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE} bytes" }
    }

    public fun toByteArray(): ByteArray = data.toByteArray()

    override fun toString(): String = data.toHex()
}

/**
 * This object contain helper functions to use musig2 in the context of spending taproot outputs.
 * In order to provide a simpler API, some operations are internally duplicated: if performance is an issue, you should
 * consider using the lower-level APIs directly (see [Session] and [KeyAggCache]).
 */
public object Musig2 {
    /**
     * Aggregate the public keys of a musig2 session into a single public key.
     * Note that this function doesn't apply any tweak: when used for taproot, it computes the internal public key, not
     * the public key exposed in the script (which is tweaked with the script tree).
     *
     * @param publicKeys public keys of all participants: callers must verify that all public keys are valid.
     */
    @JvmStatic
    public fun aggregateKeys(publicKeys: List<PublicKey>): XonlyPublicKey = KeyAggCache.create(publicKeys).first

    /**
     * @param sessionId a random, unique session ID.
     * @param privateKey signer's private key.
     * @param publicKeys public keys of all participants: callers must verify that all public keys are valid.
     */
    @JvmStatic
    public fun generateNonce(sessionId: ByteVector32, privateKey: PrivateKey, publicKeys: List<PublicKey>): Pair<SecretNonce, IndividualNonce> {
        val (_, keyAggCache) = KeyAggCache.create(publicKeys)
        return SecretNonce.generate(sessionId, privateKey, privateKey.publicKey(), message = null, keyAggCache, extraInput = null)
    }

    /**
     * Create a musig2 session for a given transaction input.
     *
     * @param tx transaction
     * @param inputIndex transaction input index
     * @param inputs outputs spent by this transaction
     * @param publicKeys signers' public keys
     * @param publicNonces signers' public nonces
     * @param scriptTree tapscript tree of the transaction's input, if it has script paths.
     */
    @JvmStatic
    public fun taprootSession(tx: Transaction, inputIndex: Int, inputs: List<TxOut>, publicKeys: List<PublicKey>, publicNonces: List<IndividualNonce>, scriptTree: ScriptTree?): Either<Throwable, Session> {
        return IndividualNonce.aggregate(publicNonces).flatMap { aggregateNonce ->
            val (aggregatePublicKey, keyAggCache) = KeyAggCache.create(publicKeys)
            val tweak = when (scriptTree) {
                null -> aggregatePublicKey.tweak(Crypto.TaprootTweak.NoScriptTweak)
                else -> aggregatePublicKey.tweak(Crypto.TaprootTweak.ScriptTweak(scriptTree))
            }
            keyAggCache.tweak(tweak, isXonly = true).map { tweakedKeyAggCache ->
                val txHash = Transaction.hashForSigningTaprootKeyPath(tx, inputIndex, inputs, SigHash.SIGHASH_DEFAULT)
                Session.create(aggregateNonce, txHash, tweakedKeyAggCache.first)
            }
        }
    }

    /**
     * Create a partial musig2 signature for the given taproot input key path.
     *
     * @param privateKey private key of the signing participant.
     * @param tx transaction spending the target taproot input.
     * @param inputIndex index of the taproot input to spend.
     * @param inputs all inputs of the spending transaction.
     * @param publicKeys public keys of all participants of the musig2 session: callers must verify that all public keys are valid.
     * @param secretNonce secret nonce of the signing participant.
     * @param publicNonces public nonces of all participants of the musig2 session.
     * @param scriptTree tapscript tree of the taproot input, if it has script paths.
     */
    @JvmStatic
    public fun signTaprootInput(
        privateKey: PrivateKey,
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        publicKeys: List<PublicKey>,
        secretNonce: SecretNonce,
        publicNonces: List<IndividualNonce>,
        scriptTree: ScriptTree?
    ): Either<Throwable, ByteVector32> {
        return taprootSession(tx, inputIndex, inputs, publicKeys, publicNonces, scriptTree).map { it.sign(secretNonce, privateKey) }
    }

    /**
     * Verify a partial musig2 signature.

     * @param partialSig partial musig2 signature.
     * @param nonce public nonce matching the secret nonce used to generate the signature.
     * @param publicKey public key for the private key used to generate the signature.
     * @param tx transaction spending the target taproot input.
     * @param inputIndex index of the taproot input to spend.
     * @param inputs all inputs of the spending transaction.
     * @param publicKeys public keys of all participants of the musig2 session: callers must verify that all public keys are valid.
     * @param publicNonces public nonces of all participants of the musig2 session.
     * @param scriptTree tapscript tree of the taproot input, if it has script paths.
     * @return true if the partial signature is valid.
     */
    @JvmStatic
    public fun verifyTaprootSignature(
        partialSig: ByteVector32,
        nonce: IndividualNonce,
        publicKey: PublicKey,
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        publicKeys: List<PublicKey>,
        publicNonces: List<IndividualNonce>,
        scriptTree: ScriptTree?
    ): Boolean {
        val session = taprootSession(tx, inputIndex, inputs, publicKeys, publicNonces, scriptTree)
        return session.map { it.verify(partialSig, nonce, publicKey) }.getOrElse { false }
    }

    /**
     * Aggregate partial musig2 signatures into a valid schnorr signature for the given taproot input key path.
     *
     * @param partialSigs partial musig2 signatures of all participants of the musig2 session.
     * @param tx transaction spending the target taproot input.
     * @param inputIndex index of the taproot input to spend.
     * @param inputs all inputs of the spending transaction.
     * @param publicKeys public keys of all participants of the musig2 session: callers must verify that all public keys are valid.
     * @param publicNonces public nonces of all participants of the musig2 session.
     * @param scriptTree tapscript tree of the taproot input, if it has script paths.
     */
    @JvmStatic
    public fun aggregateTaprootSignatures(
        partialSigs: List<ByteVector32>,
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        publicKeys: List<PublicKey>,
        publicNonces: List<IndividualNonce>,
        scriptTree: ScriptTree?
    ): Either<Throwable, ByteVector64> {
        return taprootSession(tx, inputIndex, inputs, publicKeys, publicNonces, scriptTree).flatMap { it.aggregateSigs(partialSigs) }
    }

}