/*
 * Copyright 2020 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.bitcoin

public object ScriptFlags {
    public const val SCRIPT_VERIFY_NONE: Int = 0

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    public const val SCRIPT_VERIFY_P2SH: Int = (1 shl 0)

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    public const val SCRIPT_VERIFY_STRICTENC: Int = (1 shl 1)

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    public const val SCRIPT_VERIFY_DERSIG: Int = (1 shl 2)

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    public const val SCRIPT_VERIFY_LOW_S: Int = (1 shl 3)

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    public const val SCRIPT_VERIFY_NULLDUMMY: Int = (1 shl 4)

    // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    public const val SCRIPT_VERIFY_SIGPUSHONLY: Int = (1 shl 5)

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    // (softfork safe)
    public const val SCRIPT_VERIFY_MINIMALDATA: Int = (1 shl 6)

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    public const val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS: Int = (1 shl 7)

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH.
    public const val SCRIPT_VERIFY_CLEANSTACK: Int = (1 shl 8)

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    public const val SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY: Int = (1 shl 9)


    // See BIP112 for details
    public const val SCRIPT_VERIFY_CHECKSEQUENCEVERIFY: Int = (1 shl 10)

    // support CHECKSEQUENCEVERIFY opcode
    //
    // Support segregated witness
    //
    public const val SCRIPT_VERIFY_WITNESS: Int = (1 shl 11)

    // Making v2-v16 witness program non-standard
    //
    public const val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Int = (1 shl 12)


    // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    public const val SCRIPT_VERIFY_MINIMALIF: Int = (1 shl 13)

    // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    //
    public const val SCRIPT_VERIFY_NULLFAIL: Int = (1 shl 14)

    // Public keys in segregated witness scripts must be compressed
    //
    public const val SCRIPT_VERIFY_WITNESS_PUBKEYTYPE: Int = (1 shl 15)

    // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
    //
    public const val SCRIPT_VERIFY_CONST_SCRIPTCODE: Int = (1 shl 16)

    // Taproot/Tapscript validation (BIPs 341 & 342)
    //
    public const val SCRIPT_VERIFY_TAPROOT: Int = (1 shl 17)

    // Making unknown Taproot leaf versions non-standard
    //
    public const val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Int = (1 shl 18)

    // Making unknown OP_SUCCESS non-standard
    public const val SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS: Int = (1 shl 19)

    // Making unknown public key versions (in BIP 342 scripts) non-standard
    public const val SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Int = (1 shl 20)

    /**
     * Mandatory script verification flags that all new blocks must comply with for
     * them to be valid. (but old blocks may not comply with) Currently just P2SH,
     * but in the future other flags may be added, such as a soft-fork to enforce
     * strict DER encoding.
     *
     * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
     * details.
     */
    public const val MANDATORY_SCRIPT_VERIFY_FLAGS: Int = SCRIPT_VERIFY_P2SH

    /**
     * Standard script verification flags that standard transactions will comply
     * with. However scripts violating these flags may still be present in valid
     * blocks and we must accept those blocks.
     */
    public const val STANDARD_SCRIPT_VERIFY_FLAGS: Int = MANDATORY_SCRIPT_VERIFY_FLAGS or
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
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM or
            SCRIPT_VERIFY_WITNESS_PUBKEYTYPE or
            SCRIPT_VERIFY_CONST_SCRIPTCODE or
            SCRIPT_VERIFY_TAPROOT or
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION or
            SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS or
            SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    /** For convenience, standard but not mandatory verify flags. */
    public const val STANDARD_NOT_MANDATORY_VERIFY_FLAGS: Int = STANDARD_SCRIPT_VERIFY_FLAGS and MANDATORY_SCRIPT_VERIFY_FLAGS.inv()
}