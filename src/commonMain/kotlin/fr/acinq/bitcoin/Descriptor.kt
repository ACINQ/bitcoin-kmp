package fr.acinq.bitcoin

import fr.acinq.bitcoin.DeterministicWallet.derivePrivateKey
import fr.acinq.bitcoin.DeterministicWallet.publicKey
import kotlin.jvm.JvmStatic

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

    @JvmStatic
    public fun checksum(span: String): String {
        /** A character set designed such that:
         *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
         *  - Case errors cause an offset that's a multiple of 32.
         *  - As many alphabetic characters are in the same group (while following the above restrictions).
         *
         * If p(x) gives the position of a character c in this character set, every group of 3 characters
         * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
         * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
         * affect a single symbol.
         *
         * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
         * the position within the groups.
         */
        val INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}" + "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" + "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

        /** The character set for the checksum itself (same as bech32). */
        val CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

        var c = 1L
        var cls = 0
        var clscount = 0
        span.forEach { ch ->
            val pos = INPUT_CHARSET.indexOf(ch);
            if (pos == -1) return "";
            c = polyMod(c, pos and 31); // Emit a symbol for the position inside the group, for every character.
            cls = cls * 3 + (pos shr 5); // Accumulate the group numbers
            clscount = clscount + 1
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

        var ret = StringBuilder("        ")
        for (j in 0 until 8) {
            val pos1 = (c shr (5 * (7 - j))) and 31
            val char = CHECKSUM_CHARSET.get(pos1.toInt())
            ret.set(j, char)
        }
        return ret.toString()
    }

    private fun getKeyPath(chainHash: ByteVector32): Pair<String, Int> = when (chainHash) {
        Block.RegtestGenesisBlock.hash, Block.TestnetGenesisBlock.hash -> "84'/1'/0'/0" to DeterministicWallet.tpub
        Block.LivenetGenesisBlock.hash -> "84'/0'/0'/0" to DeterministicWallet.xpub
        else -> error("invalid chain hash $chainHash")
    }

    @JvmStatic
    public fun BIP84Descriptors(chainHash: ByteVector32, master: DeterministicWallet.ExtendedPrivateKey): Pair<String, String> {
        val (keyPath, _) = getKeyPath(chainHash)
        val accountPub = publicKey(derivePrivateKey(master, KeyPath(keyPath)))
        val fingerprint = DeterministicWallet.fingerprint(master) and 0xFFFFFFFFL
        return BIP84Descriptors(chainHash, fingerprint, accountPub)
    }

    @JvmStatic
    public fun BIP84Descriptors(chainHash: ByteVector32, fingerprint: Long, accountPub: DeterministicWallet.ExtendedPublicKey): Pair<String, String> {
        val (keyPath, prefix) = getKeyPath(chainHash)
        val accountDesc = "wpkh([${fingerprint.toString(16)}/$keyPath]${DeterministicWallet.encode(accountPub, prefix)}/0/*)"
        val changeDesc = "wpkh([${fingerprint.toString(16)}/$keyPath]${DeterministicWallet.encode(accountPub, prefix)}/1/*)"
        return Pair(
            "$accountDesc#${checksum(accountDesc)}",
            "$changeDesc#${checksum(changeDesc)}"
        )
    }
}