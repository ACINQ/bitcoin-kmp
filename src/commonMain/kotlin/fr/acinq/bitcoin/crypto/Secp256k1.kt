package fr.acinq.bitcoin.crypto

expect object Secp256k1 {
    fun computePublicKey(priv: ByteArray): ByteArray

    fun parsePublicKey(pub: ByteArray): ByteArray

    fun ecdh(priv: ByteArray, pub: ByteArray): ByteArray

    fun privateKeyAdd(priv1: ByteArray, priv2: ByteArray): ByteArray

    fun privateKeyNegate(priv: ByteArray): ByteArray

    fun privateKeyMul(priv: ByteArray, tweak: ByteArray): ByteArray

    fun publicKeyAdd(pub1: ByteArray, pub2: ByteArray): ByteArray

    fun publicKeyNegate(pub: ByteArray): ByteArray

    fun publicKeyMul(pub: ByteArray, tweak: ByteArray): ByteArray

    fun sign(data: ByteArray, priv: ByteArray): ByteArray

    fun verify(data: ByteArray, sig: ByteArray, pub: ByteArray): Boolean

    fun compact2der(input: ByteArray): ByteArray

    fun der2compact(input: ByteArray): ByteArray

    fun signatureNormalize(input: ByteArray) : Pair<ByteArray, Boolean>
}