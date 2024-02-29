package fr.acinq.bitcoin.crypto

internal actual fun Sha1(): Digest = Sha1Native()

internal actual fun Sha256(): Digest = Sha256Native()

internal actual fun Sha512(): Digest = Sha512Native()
