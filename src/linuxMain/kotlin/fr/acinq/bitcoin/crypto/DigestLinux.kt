package fr.acinq.bitcoin.crypto


public actual fun Digest.Companion.sha1(): Digest = Sha1Linux()
public actual fun Digest.Companion.sha256(): Digest = Sha256Linux()
public actual fun Digest.Companion.sha512(): Digest = Sha512Linux()
