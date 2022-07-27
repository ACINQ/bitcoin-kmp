package fr.acinq.bitcoin

import fr.acinq.bitcoin.DeterministicWallet.derivePrivateKey
import fr.acinq.bitcoin.DeterministicWallet.publicKey
import kotlin.jvm.JvmStatic

/**
 * Output Script Descriptors: see https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
 */
public object Descriptor {
    private fun polyMod(cc: Long, value: Int): Long {
        var c = cc
        val c0 = c shr 35
        c = ((c and 0x7ffffffffL) shl 5) xor value.toLong()
        if ((c0 and 1L) != 0L) c = c xor 0xf5dee51989L
        if ((c0 and 2L) != 0L) c = c xor 0xa9fdca3312L
        if ((c0 and 4L) != 0L) c = c xor 0x1bab10e32dL
        if ((c0 and 8L) != 0L) c = c xor 0x3706b1677aL
        if ((c0 and 16L) != 0L) c = c xor 0x644d626ffdL
        return c
    }

    // Taken from: https://github.com/bitcoin/bitcoin/blob/207a22877330709e4462e6092c265ab55c8653ac/src/script/descriptor.cpp
    @JvmStatic
    public fun checksum(span: String): String {
        val INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}" + "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" + "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
        val CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        var c = 1L
        var cls = 0
        var clscount = 0
        span.forEach { ch ->
            val pos = INPUT_CHARSET.indexOf(ch)
            if (pos == -1) return ""
            c = polyMod(c, pos and 31) // Emit a symbol for the position inside the group, for every character.
            cls = cls * 3 + (pos shr 5) // Accumulate the group numbers
            clscount += 1
            if (clscount == 3) {
                // Emit an extra symbol representing the group numbers, for every 3 characters.
                c = polyMod(c, cls)
                cls = 0
                clscount = 0
            }
        }
        if (clscount > 0) c = polyMod(c, cls)
        for (j in 0 until 8) c = polyMod(c, 0) // Shift further to determine the checksum.
        c = c xor 1 // Prevent appending zeroes from not affecting the checksum.

        val ret = StringBuilder("        ")
        for (j in 0 until 8) {
            val pos1 = (c shr (5 * (7 - j))) and 31
            ret[j] = CHECKSUM_CHARSET[pos1.toInt()]
        }
        return ret.toString()
    }

    private fun getBIP84KeyPath(chainHash: ByteVector32): Pair<String, Int> = when (chainHash) {
        Block.RegtestGenesisBlock.hash, Block.TestnetGenesisBlock.hash -> "84'/1'/0'/0" to DeterministicWallet.tpub
        Block.LivenetGenesisBlock.hash -> "84'/0'/0'/0" to DeterministicWallet.xpub
        else -> error("invalid chain hash $chainHash")
    }

    @JvmStatic
    public fun BIP84Descriptor(chainHash: ByteVector32, master: DeterministicWallet.ExtendedPrivateKey): String {
        val (keyPath, _) = getBIP84KeyPath(chainHash)
        val accountPub = publicKey(derivePrivateKey(master, KeyPath(keyPath)))
        val fingerprint = DeterministicWallet.fingerprint(master) and 0xFFFFFFFFL
        return BIP84Descriptor(chainHash, fingerprint, accountPub)
    }

    @JvmStatic
    public fun BIP84Descriptor(chainHash: ByteVector32, fingerprint: Long, accountPub: DeterministicWallet.ExtendedPublicKey): String {
        val (keyPath, prefix) = getBIP84KeyPath(chainHash)
        val accountDesc = "wpkh([${fingerprint.toString(16)}/$keyPath]${DeterministicWallet.encode(accountPub, prefix)}/<0;1>/*)"
        return "$accountDesc#${checksum(accountDesc)}"
    }
}