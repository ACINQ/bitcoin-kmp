package fr.acinq.bitcoin.crypto

internal actual fun Sha1(): Digest = Sha1Mingw()
internal actual fun Sha256(): Digest = Sha256Mingw()
internal actual fun Sha512(): Digest = Sha512Mingw()