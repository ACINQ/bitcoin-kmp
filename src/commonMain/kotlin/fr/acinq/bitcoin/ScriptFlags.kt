package fr.acinq.bitcoin

object ScriptFlags {
    const val SCRIPT_VERIFY_NONE = 0

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    const val SCRIPT_VERIFY_P2SH = (1 shl 0)

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    const val SCRIPT_VERIFY_STRICTENC = (1 shl 1)

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    const val SCRIPT_VERIFY_DERSIG = (1 shl 2)

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    const val SCRIPT_VERIFY_LOW_S = (1 shl 3)

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    const val SCRIPT_VERIFY_NULLDUMMY = (1 shl 4)

    // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    const val SCRIPT_VERIFY_SIGPUSHONLY = (1 shl 5)

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    // (softfork safe)
    const val SCRIPT_VERIFY_MINIMALDATA = (1 shl 6)

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    const val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 shl 7)

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH.
    const val SCRIPT_VERIFY_CLEANSTACK = (1 shl 8)

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    const val SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1 shl 9)


    // See BIP112 for details
    const val SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1 shl 10)

    // support CHECKSEQUENCEVERIFY opcode
    //
    // Support segregated witness
    //
    const val SCRIPT_VERIFY_WITNESS = (1 shl 11)

    // Making v2-v16 witness program non-standard
    //
    const val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1 shl 12)


    // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    const val SCRIPT_VERIFY_MINIMALIF = (1 shl 13)

    // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    //
    const val SCRIPT_VERIFY_NULLFAIL = (1 shl 14)

    // Public keys in segregated witness scripts must be compressed
    //
    const val SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1 shl 15)

    // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
    //
    const val SCRIPT_VERIFY_CONST_SCRIPTCODE = (1 shl 16)

    /**
     * Mandatory script verification flags that all new blocks must comply with for
     * them to be valid. (but old blocks may not comply with) Currently just P2SH,
     * but in the future other flags may be added, such as a soft-fork to enforce
     * strict DER encoding.
     *
     * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
     * details.
     */
    const val MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH

    /**
     * Standard script verification flags that standard transactions will comply
     * with. However scripts violating these flags may still be present in valid
     * blocks and we must accept those blocks.
     */
    const val STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS or
            SCRIPT_VERIFY_DERSIG or
            SCRIPT_VERIFY_STRICTENC or
            SCRIPT_VERIFY_MINIMALDATA or
            SCRIPT_VERIFY_NULLDUMMY or
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS or
            SCRIPT_VERIFY_CLEANSTACK or
            SCRIPT_VERIFY_MINIMALIF or
            SCRIPT_VERIFY_NULLFAIL or
            SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY or
            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY or
            SCRIPT_VERIFY_LOW_S or
            SCRIPT_VERIFY_WITNESS or
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM

    /** For convenience, standard but not mandatory verify flags. */
    const val STANDARD_NOT_MANDATORY_VERIFY_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS and MANDATORY_SCRIPT_VERIFY_FLAGS.inv()
}