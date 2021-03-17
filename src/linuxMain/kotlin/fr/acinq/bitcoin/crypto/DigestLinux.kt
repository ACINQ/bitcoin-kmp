package fr.acinq.bitcoin.crypto


internal actual fun Sha1(): Digest = Sha1Linux()
internal actual fun Sha256(): Digest = Sha256Linux()
internal actual fun Sha512(): Digest = Sha512Linux()
