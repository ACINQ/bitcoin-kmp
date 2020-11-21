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

import fr.acinq.bitcoin.io.ByteArrayInput
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.secp256k1.Hex
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

public typealias RunnerCallback = (List<ScriptElt>, List<ByteVector>, Script.Runner.Companion.State) -> Boolean

@OptIn(ExperimentalUnsignedTypes::class)
public object Script {
    public const val MaxScriptElementSize: Int = 520
    public val True: ByteVector = ByteVector("01")
    public val False: ByteVector = ByteVector.empty

    @JvmField
    public val LockTimeThreshold: Long = 500000000L

    /**
     * parse a script from a input stream of binary data
     *
     * @param input input stream
     * @param stack initial command stack
     * @return an updated command stack
     */
    public tailrec fun parse(input: Input, stack: List<ScriptElt> = listOf()): List<ScriptElt> {
        val code = input.read()
        return when {
            code == -1 -> stack
            code == 0 -> parse(input, stack + OP_0)
            code in 1 until 0x4c -> parse(input, stack + OP_PUSHDATA(BtcSerializer.bytes(input, code), code))
            code == 0x4c -> parse(
                input,
                stack + OP_PUSHDATA(BtcSerializer.bytes(input, BtcSerializer.uint8(input).toInt()), 0x4c)
            )
            code == 0x4d -> parse(
                input,
                stack + OP_PUSHDATA(BtcSerializer.bytes(input, BtcSerializer.uint16(input).toInt()), 0x4d)
            )
            code == 0x4e -> parse(
                input,
                stack + OP_PUSHDATA(BtcSerializer.bytes(input, BtcSerializer.uint32(input).toInt()), 0x4e)
            )
            ScriptEltMapping.code2elt.containsKey(code) -> parse(
                input,
                stack + ScriptEltMapping.code2elt.getValue(code)
            )
            else -> parse(input, stack + OP_INVALID(code))
        }
    }

    @JvmStatic
    public fun parse(blob: ByteArray): List<ScriptElt> =
        if (blob.size > 10000) throw RuntimeException("script is too large") else parse(
            ByteArrayInput(blob)
        )

    @JvmStatic
    public fun parse(blob: ByteVector): List<ScriptElt> = parse(blob.toByteArray())

    @JvmStatic
    public fun parse(hex: String): List<ScriptElt> = parse(Hex.decode(hex))

    public tailrec fun write(script: List<ScriptElt>, out: Output): Unit {
        if (script.isEmpty()) return
        else {
            val head = script.first()
            val tail = script.tail()
            when (head) {
                is OP_PUSHDATA -> {
                    when {
                        head.data.size() < 0x4c && head.data.size() == head.code -> {
                            out.write(head.data.size())
                        }
                        head.data.size() < 0xff && head.code == 0x4c -> {
                            BtcSerializer.writeUInt8(0x4Cu, out)
                            BtcSerializer.writeUInt8(head.data.size().toUByte(), out)
                        }
                        head.data.size() < 0xffff && head.code == 0x4d -> {
                            BtcSerializer.writeUInt8(0x4Du, out)
                            BtcSerializer.writeUInt16(head.data.size().toUShort(), out)
                        }
                        head.data.size() < 0xffffffff && head.code == 0x4e -> {
                            BtcSerializer.writeUInt8(0x4Eu, out)
                            BtcSerializer.writeUInt32(head.data.size().toUInt(), out)
                        }
                    }
                    out.write(head.data.toByteArray())
                    return write(tail, out)
                }
                else -> {
                    out.write(ScriptEltMapping.elt2code.getValue(head))
                    return write(tail, out)
                }
            }
        }
    }

    @JvmStatic
    public fun write(script: List<ScriptElt>): ByteArray {
        val out = ByteArrayOutput()
        write(script, out)
        return out.toByteArray()
    }

    @JvmStatic
    public fun isUpgradableNop(op: ScriptElt): Boolean = when (op) {
        OP_NOP1, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10 -> true
        else -> false
    }

    @JvmStatic
    public fun isSimpleValue(op: ScriptElt): Boolean = when (op) {
        OP_1NEGATE, OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16 -> true
        else -> false
    }

    @JvmStatic
    public fun simpleValue(op: ScriptElt): Byte {
        require(isSimpleValue(op)) {}
        val value = if (op == OP_0) 0 else (ScriptEltMapping.elt2code.getValue(op) - 0x50)
        return value.toByte()
    }

    @JvmStatic
    public fun fromSimpleValue(value: Byte): ScriptElt = when (value.toInt()) {
        0 -> OP_0
        in -1..16 -> ScriptEltMapping.code2elt.getValue(value + 0x50)
        else -> throw IllegalArgumentException("cannot convert $value to a simple value operator")
    }

    @JvmStatic
    public fun isDisabled(op: ScriptElt): Boolean = when (op) {
        OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV, OP_MUL, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT -> true
        else -> false
    }

    @JvmStatic
    public fun cost(op: ScriptElt): Int = when {
        isSimpleValue(op) -> 0
        op is OP_PUSHDATA -> 0
        op == OP_RESERVED -> 0
        else -> 1
    }

    @JvmStatic
    public fun encodeNumber(value: Long): ByteVector {
        if (value == 0L) return ByteVector.empty
        else {
            val result = arrayListOf<Byte>()
            val neg = value < 0
            var absvalue = if (neg) -value else value

            while (absvalue > 0) {
                result.add((absvalue and 0xff).toByte())
                absvalue = absvalue.shr(8)
            }

            //    - If the most significant byte is >= 0x80 and the value is positive, push a
            //    new zero-byte to make the significant byte < 0x80 again.

            //    - If the most significant byte is >= 0x80 and the value is negative, push a
            //    new 0x80 byte that will be popped off when converting to an integral.

            //    - If the most significant byte is < 0x80 and the value is negative, add
            //    0x80 to it, since it will be subtracted and interpreted as a negative when
            //    converting to an integral.

            if ((result.last().toInt() and 0x80) != 0) {
                result.add(if (neg) 0x80.toByte() else 0)
            } else if (neg) {
                result[result.lastIndex] = (result[result.lastIndex].toInt() or 0x80).toByte()
            }
            return result.toByteArray().byteVector()
        }
    }

    @JvmStatic
    public fun encodeNumber(value: Int): ByteVector = encodeNumber(value.toLong())

    @JvmStatic
    public fun decodeNumber(input: ByteArray, checkMinimalEncoding: Boolean, maximumSize: Int = 4): Long {
        if (input.isEmpty()) return 0
        else if (input.size > maximumSize) throw RuntimeException("number cannot be encoded on more than $maximumSize bytes")
        else {
            if (checkMinimalEncoding) {
                // Check that the number is encoded with the minimum possible
                // number of bytes.
                //
                // If the most-significant-byte - excluding the sign bit - is zero
                // then we're not minimal. Note how this test also rejects the
                // negative-zero encoding, 0x80.
                if ((input.last().toInt() and 0x7f) == 0) {
                    // One exception: if there's more than one byte and the most
                    // significant bit of the second-most-significant-byte is set
                    // it would conflict with the sign bit. An example of this case
                    // is +-255, which encode to 0xff00 and 0xff80 respectively.
                    // (big-endian).
                    if (input.size <= 1 || (input[input.size - 2].toInt() and 0x80) == 0) {
                        throw RuntimeException("non-minimally encoded script number")
                    }
                }
            }
            var result = 0L
            for (i in 0..input.lastIndex) {
                result = result or (input[i].toLong() and 0xffL).shl(8 * i)
            }

            // If the input vector's most significant byte is 0x80, remove it from
            // the result's msb and return a negative.
            return if ((input.last().toInt() and 0x80) != 0)
                -(result and (0x80L.shl(8 * (input.size - 1))).inv())
            else
                result
        }
    }

    @JvmStatic
    public fun decodeNumber(input: ByteVector, checkMinimalEncoding: Boolean, maximumSize: Int = 4): Long =
        decodeNumber(input.toByteArray(), checkMinimalEncoding, maximumSize)

    public fun castToBoolean(input: List<Byte>): Boolean {
        return if (input.isEmpty()) false
        else {
            val input1 = input.reversed()
            when {
                input1.first() == 0x80.toByte() && !input1.tail().any { it != 0.toByte() } -> false
                input.any { it != 0.toByte() } -> true
                else -> false
            }
        }
    }

    public fun castToBoolean(input: ByteArray): Boolean = castToBoolean(input.asList())

    public fun castToBoolean(input: ByteVector): Boolean = castToBoolean(input.toByteArray())

    @JvmStatic
    public fun isPushOnly(script: List<ScriptElt>): Boolean = !script.any {
        when {
            isSimpleValue(it) -> false
            it is OP_PUSHDATA -> false
            else -> true
        }
    }

    @JvmStatic
    public fun isPayToScript(script: ByteArray): Boolean =
        script.size == 23 && script[0] == ScriptEltMapping.elt2code.getValue(OP_HASH160)
            .toByte() && script[1] == 0x14.toByte() && script[22] == ScriptEltMapping.elt2code.getValue(OP_EQUAL)
            .toByte()

    /**
     * Creates a m-of-n multisig script.
     *
     * @param m       is the number of required signatures
     * @param pubkeys are the public keys signatures will be checked against (there should be at least as many public keys
     *                as required signatures)
     * @return a multisig redeem script
     */
    @JvmStatic
    public fun createMultiSigMofN(m: Int, pubkeys: List<PublicKey>): List<ScriptElt> {
        require(m in 1..16) { "number of required signatures is $m, should be between 1 and 16" }
        require(pubkeys.count() in 1..16) { "number of public keys is ${pubkeys.size}, should be between 1 and 16" }
        require(m <= pubkeys.count()) { "The required number of signatures shouldn't be greater than the number of public keys" }
        val op_m = ScriptEltMapping.code2elt.getValue(m + 0x50)
        // 1 -> OP_1, 2 -> OP_2, ... 16 -> OP_16
        val op_n = ScriptEltMapping.code2elt.getValue(pubkeys.count() + 0x50)
        return listOf(op_m) + pubkeys.map { OP_PUSHDATA(it) } + listOf(op_n, OP_CHECKMULTISIG)
    }

    /**
     *
     * @param pubKeyHash public key hash
     * @return a pay-to-public-key-hash script
     */
    @JvmStatic
    public fun pay2pkh(pubKeyHash: ByteArray): List<ScriptElt> {
        require(pubKeyHash.size == 20) { "pubkey hash length must be 20 bytes" }
        return listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(pubKeyHash), OP_EQUALVERIFY, OP_CHECKSIG)
    }

    @JvmStatic
    public fun isPay2pkh(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 5 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2].isPush(20) && script[3] == OP_EQUALVERIFY && script[4] == OP_CHECKSIG -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2pkh(script: ByteArray): Boolean = isPay2pkh(Script.parse(script))

    @JvmStatic
    public fun isPay2sh(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 3 && script[0] == OP_HASH160 && script[1].isPush(20) && script[2] == OP_EQUAL -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2sh(script: ByteArray): Boolean = isPay2sh(Script.parse(script))

    @JvmStatic
    public fun isPay2wpkh(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 2 && script[0] == OP_0 && script[1].isPush(20) -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2wpkh(script: ByteArray): Boolean = isPay2wpkh(Script.parse(script))

    @JvmStatic
    public fun isPay2wsh(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 2 && script[0] == OP_0 && script[1].isPush(32) -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2wsh(script: ByteArray): Boolean = isPay2wsh(Script.parse(script))

    /**
     *
     * @param pubKey public key
     * @return a pay-to-public-key-hash script
     */
    @JvmStatic
    public fun pay2pkh(pubKey: PublicKey): List<ScriptElt> = pay2pkh(pubKey.hash160())

    /**
     *
     * @param script bitcoin script
     * @return a pay-to-script script
     */
    @JvmStatic
    public fun pay2sh(script: List<ScriptElt>): List<ScriptElt> = pay2sh(Script.write(script))

    /**
     *
     * @param script bitcoin script
     * @return a pay-to-script script
     */
    @JvmStatic
    public fun pay2sh(script: ByteArray): List<ScriptElt> = listOf(OP_HASH160, OP_PUSHDATA(Crypto.hash160(script)), OP_EQUAL)

    /**
     *
     * @param script bitcoin script
     * @return a pay-to-witness-script script
     */
    @JvmStatic
    public fun pay2wsh(script: List<ScriptElt>): List<ScriptElt> = pay2wsh(Script.write(script))

    /**
     *
     * @param script bitcoin script
     * @return a pay-to-witness-script script
     */
    @JvmStatic
    public fun pay2wsh(script: ByteArray): List<ScriptElt> = listOf(OP_0, OP_PUSHDATA(Crypto.sha256(script)))

    /**
     *
     * @param script bitcoin script
     * @return a pay-to-witness-script script
     */
    @JvmStatic
    public fun pay2wsh(script: ByteVector): List<ScriptElt> = pay2wsh(script.toByteArray())

    /**
     *
     * @param pubKeyHash public key hash
     * @return a pay-to-witness-public-key-hash script
     */
    @JvmStatic
    public fun pay2wpkh(pubKeyHash: ByteArray): List<ScriptElt> {
        require(pubKeyHash.size == 20) { "pubkey hash length must be 20 bytes" }
        return listOf(OP_0, OP_PUSHDATA(pubKeyHash))
    }

    /**
     *
     * @param pubKey public key
     * @return a pay-to-witness-public-key-hash script
     */
    @JvmStatic
    public fun pay2wpkh(pubKey: PublicKey): List<ScriptElt> = pay2wpkh(pubKey.hash160())

    public fun removeSignature(script: List<ScriptElt>, signature: ByteVector): List<ScriptElt> {
        val toRemove = OP_PUSHDATA(signature)
        return script.filterNot { it == toRemove }
    }

    public fun removeSignatures(script: List<ScriptElt>, sigs: List<ByteVector>): List<ScriptElt> =
        sigs.fold(script, Script::removeSignature)

    public fun checkLockTime(lockTime: Long, tx: Transaction, inputIndex: Int): Boolean {
        // There are two kinds of nLockTime: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nLockTime < LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if (!(
                    (tx.lockTime < Transaction.LOCKTIME_THRESHOLD && lockTime < Transaction.LOCKTIME_THRESHOLD) ||
                            (tx.lockTime >= Transaction.LOCKTIME_THRESHOLD && lockTime >= Transaction.LOCKTIME_THRESHOLD)
                    )
        )
            return false

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (lockTime > tx.lockTime)
            return false

        // Finally the nLockTime feature can be disabled and thus
        // CHECKLOCKTIMEVERIFY bypassed if every txin has been
        // finalized by setting nSequence to maxint. The
        // transaction would be allowed into the blockchain, making
        // the opcode ineffective.
        //
        // Testing if this vin is not final is sufficient to
        // prevent this condition. Alternatively we could test all
        // inputs, but testing just this input minimizes the data
        // required to prove correct CHECKLOCKTIMEVERIFY execution.
        if (tx.txIn.elementAt(inputIndex).isFinal)
            return false

        return true
    }

    public fun checkSequence(sequence: Long, tx: Transaction, inputIndex: Int): Boolean {
        // Relative lock times are supported by comparing the passed
        // in operand to the sequence number of the input.
        val txToSequence = tx.txIn.elementAt(inputIndex).sequence

        // Fail if the transaction's version number is not set high
        // enough to trigger BIP 68 rules.
        if (tx.version < 2)
            return false

        // Sequence numbers with their most significant bit set are not
        // consensus constrained. Testing that the transaction's sequence
        // number do not have this bit set prevents using this property
        // to get around a CHECKSEQUENCEVERIFY check.
        if ((txToSequence and TxIn.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0L)
            return false

        // Mask off any bits that do not have consensus-enforced meaning
        // before doing the integer comparisons
        val nLockTimeMask = TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG or TxIn.SEQUENCE_LOCKTIME_MASK
        val txToSequenceMasked = txToSequence and nLockTimeMask
        val nSequenceMasked = sequence and nLockTimeMask

        // There are two kinds of nSequence: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nSequenceMasked being tested is the same as
        // the nSequenceMasked in the transaction.
        if (!(
                    (txToSequenceMasked < TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked < TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG) ||
                            (txToSequenceMasked >= TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG)
                    )
        ) {
            return false
        }

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nSequenceMasked > txToSequenceMasked)
            return false

        return true
    }

    public fun <T> List<T>.tail(): List<T> {
        require(this.isNotEmpty()) { "tail of empty list" }
        return this.drop(1)
    }

    public fun <T> List<T>.dropCheck(n: Int): List<T> {
        require(this.size >= n) { "cannot drop $n elements on a list of $size elements" }
        return this.drop(n)
    }

    /**
     * Execution context of a tx script. A script is always executed in the "context" of a transaction that is being
     * verified.
     *
     * @param tx         transaction that is being verified
     * @param inputIndex 0-based index of the tx input that is being processed
     */
    public data class Context(val tx: Transaction, val inputIndex: Int, val amount: Satoshi) {
        init {
            require(inputIndex >= 0 && inputIndex < tx.txIn.count()) { "invalid input index" }
        }
    }

    public class Runner(
        public val context: Script.Context,
        public val scriptFlag: Int = ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS,
        public val callback: RunnerCallback? = null
    ) {
        public companion object {
            /**
             * This class represents the state of the script execution engine
             *
             * @param conditions current "position" wrt if/notif/else/endif
             * @param altstack   initial alternate stack
             * @param opCount    initial op count
             * @param scriptCode initial script (can be modified by OP_CODESEPARATOR for example)
             */
            public data class State(
                val conditions: List<Boolean>,
                val altstack: List<ByteVector>,
                val opCount: Int,
                val scriptCode: List<ScriptElt>
            )
        }

        /**
         * @param pubKey public key
         * @param sigBytes signature, in Bitcoin format (DER encoded + 1 trailing sighash bytes)
         * @param scriptCode current script code
         * @param signatureVersion version (legacy or segwit)
         * @return true if the signature is valid
         */
        public fun checkSignature(
            pubKey: ByteArray,
            sigBytes: ByteArray,
            scriptCode: ByteArray,
            signatureVersion: Int
        ): Boolean {
            val check = if (sigBytes.isEmpty()) false
            else if (!Crypto.checkSignatureEncoding(sigBytes, scriptFlag)) {
                throw RuntimeException("invalid signature encoding")
            } else if (!Crypto.checkPubKeyEncoding(pubKey, scriptFlag, signatureVersion)) {
                throw RuntimeException("invalid public key encoding")
            } else if (!Crypto.isPubKeyValid(pubKey)) {
                false
            } // see how this is different from above ?
            else {
                val sigHashFlags = sigBytes.last().toInt() and 0xff
                // sig hash is the last byte
                val sigBytes1 = sigBytes.dropLast(1).toByteArray() // drop sig hash
                if (sigBytes1.isEmpty()) false
                else {
                    val hash = Transaction.hashForSigning(
                        context.tx,
                        context.inputIndex,
                        scriptCode,
                        sigHashFlags,
                        context.amount,
                        signatureVersion
                    )
                    // signature is normalized here, but high-S correctness has already been checked
                    val normalized = Crypto.normalize(sigBytes1).first
                    val pub = PublicKey(pubKey)
                    val result = Crypto.verifySignature(hash, normalized, pub)
                    result
                }
            }
            return check
        }

        public fun checkSignature(
            pubKey: ByteVector,
            sigBytes: ByteVector,
            scriptCode: ByteVector,
            signatureVersion: Int
        ): Boolean =
            checkSignature(pubKey.toByteArray(), sigBytes.toByteArray(), scriptCode.toByteArray(), signatureVersion)

        public tailrec fun checkSignatures(
            pubKeys: List<ByteVector>,
            sigs: List<ByteVector>,
            scriptCode: ByteVector,
            signatureVersion: Int
        ): Boolean {
            return when {
                sigs.count() == 0 -> true
                sigs.count() > pubKeys.count() -> false
                !Crypto.checkSignatureEncoding(
                    sigs.first().toByteArray(),
                    scriptFlag
                ) -> throw RuntimeException("invalid signature")
                else -> {
                    if (checkSignature(pubKeys.first(), sigs.first(), scriptCode, signatureVersion))
                        checkSignatures(pubKeys.tail(), sigs.tail(), scriptCode, signatureVersion)
                    else
                        checkSignatures(pubKeys.tail(), sigs, scriptCode, signatureVersion)
                }
            }
        }

        public fun checkMinimalEncoding(): Boolean = (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALDATA) != 0

        public fun decodeNumber(input: ByteVector, maximumSize: Int = 4): Long =
            decodeNumber(input.toByteArray(), checkMinimalEncoding(), maximumSize)

        public fun decodeNumber(input: ByteArray, maximumSize: Int = 4): Long =
            decodeNumber(input, checkMinimalEncoding(), maximumSize)

        public fun run(script: ByteArray, signatureVersion: Int): List<ByteVector> =
            run(parse(script), listOf(), signatureVersion)

        public fun run(script: List<ScriptElt>, signatureVersion: Int): List<ByteVector> =
            run(script, listOf(), signatureVersion)

        public fun run(script: ByteArray, stack: List<ByteVector>, signatureVersion: Int): List<ByteVector> =
            run(parse(script), stack, signatureVersion)

        public fun run(script: ByteVector, stack: List<ByteVector>, signatureVersion: Int): List<ByteVector> =
            run(script.toByteArray(), stack, signatureVersion)

        public fun run(script: List<ScriptElt>, stack: List<ByteVector>, signatureVersion: Int): List<ByteVector> =
            run(
                script,
                stack,
                Script.Runner.Companion.State(
                    conditions = listOf(),
                    altstack = listOf(),
                    opCount = 0,
                    scriptCode = script
                ),
                signatureVersion
            )

        public tailrec fun run(
            script: List<ScriptElt>,
            stack: List<ByteVector>,
            state: Runner.Companion.State = Runner.Companion.State(
                conditions = listOf(),
                altstack = listOf(),
                opCount = 0,
                scriptCode = script
            ),
            signatureVersion: Int
        ): List<ByteVector> {
            callback?.invoke(script, stack, state)
            if ((stack.size + state.altstack.size) > 1000) throw RuntimeException("stack is too large: stack size = ${stack.size} alt stack size = ${state.altstack.size}")
            if (state.opCount > 201) throw RuntimeException("operation count is over the limit")
            when {
                // first, things that are always checked even in non-executed IF branches
                script.isEmpty() && !state.conditions.isEmpty() -> throw RuntimeException("IF/ENDIF imbalance")
                script.isEmpty() -> return stack
            }
            val head = script.first()
            if (isDisabled(head)) throw RuntimeException("${script.first()} is disabled")
            val tail = script.tail()

            when {
                head == OP_CODESEPARATOR && signatureVersion == SigVersion.SIGVERSION_BASE && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0 -> throw RuntimeException(
                    "Using OP_CODESEPARATOR in non-witness script"
                )
                head == OP_VERIF -> throw RuntimeException("OP_VERIF is always invalid")
                head == OP_VERNOTIF -> throw RuntimeException("OP_VERNOTIF is always invalid")
                head is OP_PUSHDATA && head.data.size() > MaxScriptElementSize -> throw RuntimeException("Push value size limit exceeded")
                // check whether we are in a non-executed IF branch
                head == OP_IF && state.conditions.any { !it } ->
                    return run(
                        tail,
                        stack,
                        state.copy(conditions = listOf(false) + state.conditions, opCount = state.opCount + 1),
                        signatureVersion
                    )
                head == OP_IF -> {
                    val stackhead = stack.first()
                    val stacktail = stack.tail()
                    return when {
                        stackhead == True && signatureVersion == fr.acinq.bitcoin.SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 ->
                            run(
                                tail,
                                stacktail,
                                state.copy(conditions = listOf(true) + state.conditions, opCount = state.opCount + 1),
                                signatureVersion
                            )
                        stackhead == False && signatureVersion == fr.acinq.bitcoin.SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 ->
                            run(
                                tail,
                                stacktail,
                                state.copy(conditions = listOf(false) + state.conditions, opCount = state.opCount + 1),
                                signatureVersion
                            )
                        signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 ->
                            throw RuntimeException("OP_IF argument must be minimal")
                        castToBoolean(stackhead) ->
                            run(
                                tail,
                                stacktail,
                                state.copy(conditions = listOf(true) + state.conditions, opCount = state.opCount + 1),
                                signatureVersion
                            )
                        else -> {
                            run(
                                tail,
                                stacktail,
                                state.copy(conditions = listOf(false) + state.conditions, opCount = state.opCount + 1),
                                signatureVersion
                            )
                        }
                    }
                }
                head == OP_NOTIF && state.conditions.any { !it } ->
                    return run(
                        tail,
                        stack,
                        state.copy(conditions = listOf(true) + state.conditions, opCount = state.opCount + 1),
                        signatureVersion
                    )
                head == OP_NOTIF -> {
                    val stackhead = stack.first()
                    val stacktail = stack.tail()
                    return when {
                        stackhead == False && signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 ->
                            run(
                                tail,
                                stacktail,
                                state.copy(conditions = listOf(true) + state.conditions, opCount = state.opCount + 1),
                                signatureVersion
                            )
                        stackhead == True && signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 ->
                            run(
                                tail,
                                stacktail,
                                state.copy(conditions = listOf(false) + state.conditions, opCount = state.opCount + 1),
                                signatureVersion
                            )
                        signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 ->
                            throw RuntimeException("OP_NOTIF argument must be minimal")
                        castToBoolean(stackhead) ->
                            run(
                                tail,
                                stacktail,
                                state.copy(conditions = listOf(false) + state.conditions, opCount = state.opCount + 1),
                                signatureVersion
                            )
                        else -> {
                            run(
                                tail,
                                stacktail,
                                state.copy(conditions = listOf(true) + state.conditions, opCount = state.opCount + 1),
                                signatureVersion
                            )
                        }
                    }
                }
                head == OP_ELSE -> return run(
                    tail,
                    stack,
                    state.copy(
                        conditions = listOf(!state.conditions.first()) + state.conditions.tail(),
                        opCount = state.opCount + 1
                    ),
                    signatureVersion
                )
                head == OP_ENDIF -> return run(
                    tail,
                    stack,
                    state.copy(conditions = state.conditions.tail(), opCount = state.opCount + 1),
                    signatureVersion
                )
                state.conditions.any { !it } -> return run(
                    tail,
                    stack,
                    state.copy(opCount = state.opCount + cost(head)),
                    signatureVersion
                )
                // and now, things that are checked only in an executed IF branch
                head == OP_0 -> return run(tail, listOf(False) + stack, state, signatureVersion)
                isSimpleValue(head) -> return run(
                    tail,
                    listOf(encodeNumber(simpleValue(head).toInt())) + stack,
                    state,
                    signatureVersion
                )
                head == OP_NOP -> return run(tail, stack, state.copy(opCount = state.opCount + 1), signatureVersion)
                isUpgradableNop(head) && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0) -> throw RuntimeException(
                    "use of upgradable NOP is discouraged"
                )
                isUpgradableNop(head) -> return run(
                    tail,
                    stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_1ADD && stack.isEmpty() -> throw RuntimeException("cannot run OP_1ADD on am empty stack")
                head == OP_1ADD -> return run(
                    tail,
                    listOf(encodeNumber(decodeNumber(stack.first()) + 1)) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_1SUB && stack.isEmpty() -> throw RuntimeException("cannot run OP_1SUB on am empty stack")
                head == OP_1SUB -> return run(
                    tail,
                    listOf(encodeNumber(decodeNumber(stack.first()) - 1)) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_ABS && stack.isEmpty() -> throw RuntimeException("cannot run OP_ABS on am empty stack")
                head == OP_ABS -> return run(
                    tail,
                    listOf(encodeNumber(kotlin.math.abs(decodeNumber(stack.first())))) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_ADD && stack.size < 2 -> throw RuntimeException("cannot run OP_ADD on a stack with less than 2 elements")
                head == OP_ADD -> {
                    val x = decodeNumber(stack[0])
                    val y = decodeNumber(stack[1])
                    val result = x + y
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_BOOLAND && stack.size < 2 -> throw RuntimeException("cannot run OP_BOOLAND on a stack with less than 2 elements")
                head == OP_BOOLAND -> {
                    val x = decodeNumber(stack[0])
                    val y = decodeNumber(stack[1])
                    val result = if (x != 0L && y != 0L) 1L else 0L
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_BOOLOR && stack.size < 2 -> throw RuntimeException("cannot run OP_BOOLOR on a stack with less than 2 elements")
                head == OP_BOOLOR -> {
                    val x = decodeNumber(stack[0])
                    val y = decodeNumber(stack[1])
                    val result = if (x != 0L || y != 0L) 1L else 0L
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_CHECKLOCKTIMEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) != 0) && stack.isEmpty() -> throw RuntimeException(
                    "cannot run OP_CHECKLOCKTIMEVERIFY on an empty stack"
                )
                head == OP_CHECKLOCKTIMEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) != 0) -> {
                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    val locktime = decodeNumber(stack.first(), maximumSize = 5)
                    if (locktime < 0) throw RuntimeException("CLTV lock time cannot be negative")
                    if (!checkLockTime(
                            locktime,
                            context.tx,
                            context.inputIndex
                        )
                    ) throw RuntimeException("unsatisfied CLTV lock time")
                    // stack is not popped: we use stack here and not stacktail !!
                    return run(tail, stack, state.copy(opCount = state.opCount + 1), signatureVersion)
                }
                head == OP_CHECKLOCKTIMEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0) -> throw RuntimeException(
                    "use of upgradable NOP is discouraged"
                )
                head == OP_CHECKLOCKTIMEVERIFY -> return run(
                    tail,
                    stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_CHECKSEQUENCEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) != 0) && stack.isEmpty() -> throw RuntimeException(
                    "cannot run OP_CHECKSEQUENCEVERIFY on an empty stack"
                )
                head == OP_CHECKSEQUENCEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) != 0) -> {
                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    val sequence = decodeNumber(stack.first(), maximumSize = 5)
                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (sequence < 0) throw RuntimeException("CSV lock time cannot be negative")

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((sequence and TxIn.Companion.SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0L) {
                        // Actually compare the specified inverse sequence number
                        // with the input.
                        if (!checkSequence(
                                sequence,
                                context.tx,
                                context.inputIndex
                            )
                        ) throw RuntimeException("unsatisfied CSV lock time")
                    }

                    // stack is not popped: we use stack here and not stacktail !!
                    return run(tail, stack, state.copy(opCount = state.opCount + 1), signatureVersion)
                }
                head == OP_CHECKSEQUENCEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0) -> throw RuntimeException(
                    "use of upgradable NOP is discouraged"
                )
                head == OP_CHECKSEQUENCEVERIFY -> return run(
                    tail,
                    stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_CHECKSIG && stack.size < 2 -> throw RuntimeException("Cannot perform OP_CHECKSIG on a stack with less than 2 elements")
                head == OP_CHECKSIG -> {
                    // remove signature from script
                    val pubKey = stack[0]
                    val sigBytes = stack[1]
                    val scriptCode1 = if (signatureVersion == SigVersion.SIGVERSION_BASE) {
                        val scriptCode1 = removeSignature(state.scriptCode, sigBytes)
                        if (scriptCode1.size != state.scriptCode.size && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0) {
                            throw RuntimeException("Signature is found in scriptCode")
                        }
                        scriptCode1
                    } else state.scriptCode
                    val success = checkSignature(
                        pubKey.toByteArray(),
                        sigBytes.toByteArray(),
                        write(scriptCode1),
                        signatureVersion
                    )
                    if (!success && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_NULLFAIL) != 0) {
                        require(sigBytes.isEmpty()) { "Signature must be zero for failed CHECKSIG operation" }
                    }
                    return run(
                        tail,
                        listOf(if (success) True else False) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_CHECKSIGVERIFY -> return run(
                    listOf(OP_CHECKSIG, OP_VERIFY) + tail,
                    stack,
                    state.copy(opCount = state.opCount - 1),
                    signatureVersion
                )
                head == OP_CHECKMULTISIG -> {
                    // pop public keys
                    val m = decodeNumber(stack.first()).toInt()
                    if (m < 0 || m > 20) throw RuntimeException("OP_CHECKMULTISIG: invalid number of public keys")
                    val nextOpCount = state.opCount + 1 + m
                    if (nextOpCount > 201) throw RuntimeException("operation count is over the limit")
                    val stack1 = stack.tail()
                    val pubKeys = stack1.take(m)
                    val stack2 = stack1.dropCheck(m)

                    // pop signatures
                    val n = decodeNumber(stack2.first()).toInt()
                    if (n < 0 || n > m) throw RuntimeException("OP_CHECKMULTISIG: invalid number of signatures")
                    val stack3 = stack2.tail()
                    // check that we have at least n + 1 items on the stack (+1 because of a bug in the reference client)
                    require(stack3.size >= n + 1) { "invalid stack operation" }
                    val sigs = stack3.take(n)
                    if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_NULLDUMMY) != 0) require(stack3[n].size() == 0) { "multisig dummy is not empty" }
                    val stack4 = stack3.dropCheck(n + 1)

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    val scriptCode1 = if (signatureVersion == SigVersion.SIGVERSION_BASE) {
                        val scriptCode1 = removeSignatures(state.scriptCode, sigs)
                        if (scriptCode1.size != state.scriptCode.size && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0) {
                            throw RuntimeException("Signature is found in scriptCode")
                        }
                        scriptCode1
                    } else {
                        state.scriptCode
                    }
                    val success = checkSignatures(pubKeys, sigs, write(scriptCode1).byteVector(), signatureVersion)
                    if (!success && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_NULLFAIL) != 0) {
                        sigs.forEach { require(it.isEmpty()) { "Signature must be zero for failed CHECKMULTISIG operation" } }
                    }
                    return run(
                        tail,
                        listOf(if (success) True else False) + stack4,
                        state.copy(opCount = nextOpCount),
                        signatureVersion
                    )
                }
                head == OP_CHECKMULTISIGVERIFY -> return run(
                    listOf(OP_CHECKMULTISIG, OP_VERIFY) + tail,
                    stack,
                    state.copy(opCount = state.opCount - 1),
                    signatureVersion
                )
                head == OP_CODESEPARATOR -> return run(
                    tail,
                    stack,
                    state.copy(opCount = state.opCount + 1, scriptCode = tail),
                    signatureVersion
                )
                head == OP_DEPTH -> return run(
                    tail,
                    listOf(encodeNumber(stack.size)) + stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_SIZE && stack.isEmpty() -> throw RuntimeException("Cannot run OP_SIZE on an empty stack")
                head == OP_SIZE -> return run(
                    tail,
                    listOf(encodeNumber(stack.first().size())) + stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_DROP -> return run(
                    tail,
                    stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_2DROP -> return run(
                    tail,
                    stack.dropCheck(2),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_DUP -> return run(
                    tail,
                    listOf(stack.first()) + stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_2DUP && stack.size < 2 -> throw RuntimeException("Cannot perform OP_2DUP on a stack with less than 2 elements")
                head == OP_2DUP -> {
                    val x1 = stack[0]
                    val x2 = stack[1]
                    return run(
                        tail,
                        listOf(x1, x2, x1, x2) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_3DUP && stack.size < 3 -> throw RuntimeException("Cannot perform OP_3DUP on a stack with less than 2 elements")
                head == OP_3DUP -> {
                    val x1 = stack[0]
                    val x2 = stack[1]
                    val x3 = stack[2]
                    return run(
                        tail,
                        listOf(x1, x2, x3, x1, x2, x3) + stack.dropCheck(3),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_EQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_EQUAL on a stack with less than 2 elements")
                head == OP_EQUAL && stack[0] != stack[1] -> return run(
                    tail,
                    listOf(False) + stack.dropCheck(2),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_EQUAL -> return run(
                    tail,
                    listOf(True) + stack.dropCheck(2),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_EQUALVERIFY && stack.size < 2 -> throw RuntimeException("Cannot perform OP_EQUALVERIFY on a stack with less than 2 elements")
                head == OP_EQUALVERIFY && stack[0] != stack[1] -> throw RuntimeException("OP_EQUALVERIFY failed: elements are different")
                head == OP_EQUALVERIFY -> return run(
                    tail,
                    stack.dropCheck(2),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_FROMALTSTACK -> return run(
                    tail,
                    listOf(state.altstack.first()) + stack,
                    state.copy(altstack = state.altstack.tail()),
                    signatureVersion
                )
                head == OP_HASH160 -> return run(
                    tail,
                    listOf(Crypto.hash160(stack.first()).byteVector()) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_HASH256 -> return run(
                    tail,
                    listOf(Crypto.hash256(stack.first()).byteVector()) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_IFDUP && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_IFDUP on an empty stack")
                head == OP_IFDUP && castToBoolean(stack.first()) -> return run(
                    tail,
                    listOf(stack.first()) + stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_IFDUP -> return run(tail, stack, state.copy(opCount = state.opCount + 1), signatureVersion)
                head == OP_LESSTHAN && stack.size < 2 -> throw RuntimeException("Cannot perform OP_LESSTHAN on a stack with less than 2 elements")
                head == OP_LESSTHAN -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = if (x2 < x1) 1 else 0
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_LESSTHANOREQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_LESSTHANOREQUAL on a stack with less than 2 elements")
                head == OP_LESSTHANOREQUAL -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = if (x2 <= x1) 1 else 0
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_GREATERTHAN && stack.size < 2 -> throw RuntimeException("Cannot perform OP_GREATERTHAN on a stack with less than 2 elements")
                head == OP_GREATERTHAN -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = if (x2 > x1) 1 else 0
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_GREATERTHANOREQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_GREATERTHANOREQUAL on a stack with less than 2 elements")
                head == OP_GREATERTHANOREQUAL -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = if (x2 >= x1) 1 else 0
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_MAX && stack.size < 2 -> throw RuntimeException("Cannot perform OP_MAX on a stack with less than 2 elements")
                head == OP_MAX -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = if (x2 > x1) x2 else x1
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_MIN && stack.size < 2 -> throw RuntimeException("Cannot perform OP_MIN on a stack with less than 2 elements")
                head == OP_MIN -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = if (x2 < x1) x2 else x1
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_NEGATE && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_NEGATE on an empty stack")
                head == OP_NEGATE -> return run(
                    tail,
                    listOf(encodeNumber(-decodeNumber(stack.first()))) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_NIP && stack.size < 2 -> throw RuntimeException("Cannot perform OP_NIP on a stack with less than 2 elements")
                head == OP_NIP -> return run(
                    tail,
                    listOf(stack.first()) + stack.dropCheck(2),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_NOT && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_NOT on an empty stack")
                head == OP_NOT -> return run(
                    tail,
                    listOf(encodeNumber(if (decodeNumber(stack.first()) == 0L) 1 else 0)) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_0NOTEQUAL && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_0NOTEQUAL on an empty stack")
                head == OP_0NOTEQUAL -> return run(
                    tail,
                    listOf(encodeNumber(if (decodeNumber(stack.first()) == 0L) 0 else 1)) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_NUMEQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_NUMEQUAL on a stack with less than 2 elements")
                head == OP_NUMEQUAL -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = if (x1 == x2) 1 else 0
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_NUMEQUALVERIFY && stack.size < 2 -> throw RuntimeException("Cannot perform OP_NUMEQUALVERIFY on a stack with less than 2 elements")
                head == OP_NUMEQUALVERIFY -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    if (x1 != x2) throw RuntimeException("OP_NUMEQUALVERIFY failed")
                    return run(tail, stack.dropCheck(2), state.copy(opCount = state.opCount + 1), signatureVersion)
                }
                head == OP_NUMNOTEQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_NUMNOTEQUAL on a stack with less than 2 elements")
                head == OP_NUMNOTEQUAL -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = if (x1 != x2) 1 else 0
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_OVER && stack.size < 2 -> throw RuntimeException("Cannot perform OP_OVER on a stack with less than 2 elements")
                head == OP_OVER -> return run(
                    tail,
                    listOf(stack[1]) + stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_2OVER && stack.size < 4 -> throw RuntimeException("Cannot perform OP_2OVER on a stack with less than 2 elements")
                head == OP_2OVER -> return run(
                    tail,
                    listOf(stack[2], stack[3]) + stack,
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_PICK && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_PICK on an empty stack")
                head == OP_PICK -> {
                    val n = decodeNumber(stack.first()).toInt()
                    return run(
                        tail,
                        listOf(stack.tail().elementAt(n)) + stack.tail(),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head is OP_PUSHDATA && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALDATA) != 0) && !OP_PUSHDATA.isMinimal(
                    head.data.toByteArray(),
                    head.code
                ) -> throw RuntimeException("not minimal push")
                head is OP_PUSHDATA -> return run(tail, listOf(head.data) + stack, state, signatureVersion)
                head == OP_ROLL && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_ROLL on an empty stack")
                head == OP_ROLL -> {
                    val n = decodeNumber(stack.first()).toInt()
                    val stacktail = stack.tail()
                    return run(
                        tail,
                        listOf(stacktail[n]) + stacktail.take(n) + stacktail.takeLast(stacktail.size - 1 - n),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_ROT && stack.size < 3 -> throw RuntimeException("Cannot perform OP_ROT on a stack with less than 3 elements")
                head == OP_ROT -> return run(
                    tail,
                    listOf(stack[2], stack[0], stack[1]) + stack.dropCheck(3),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_2ROT && stack.size < 6 -> throw RuntimeException("Cannot perform OP_2ROT on a stack with less than 6 elements")
                head == OP_2ROT -> return run(
                    tail,
                    listOf(stack[4], stack[5], stack[0], stack[1], stack[2], stack[3]) + stack.dropCheck(6),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_RIPEMD160 -> return run(
                    tail,
                    listOf(Crypto.ripemd160(stack.first()).byteVector()) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_SHA1 -> return run(
                    tail,
                    listOf(Crypto.sha1(stack.first()).byteVector()) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_SHA256 -> return run(
                    tail,
                    listOf(Crypto.sha256(stack.first()).byteVector()) + stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_SUB && stack.size < 2 -> throw RuntimeException("Cannot perform OP_SUB on a stack with less than 2 elements")
                head == OP_SUB -> {
                    val x1 = decodeNumber(stack[0])
                    val x2 = decodeNumber(stack[1])
                    val result = x2 - x1
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(2),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                head == OP_SWAP && stack.size < 2 -> throw RuntimeException("Cannot perform OP_SWAP on a stack with less than 2 elements")
                head == OP_SWAP -> return run(
                    tail,
                    listOf(stack[1], stack[0]) + stack.dropCheck(2),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_2SWAP && stack.size < 4 -> throw RuntimeException("Cannot perform OP_2SWAP on a stack with less than 4 elements")
                head == OP_2SWAP -> return run(
                    tail,
                    listOf(stack[2], stack[3], stack[0], stack[1]) + stack.dropCheck(4),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_TOALTSTACK -> return run(
                    tail,
                    stack.tail(),
                    state.copy(altstack = listOf(stack.first()) + state.altstack),
                    signatureVersion
                )
                head == OP_TUCK && stack.size < 2 -> throw RuntimeException("Cannot perform OP_TUCK on a stack with less than 2 elements")
                head == OP_TUCK -> return run(
                    tail,
                    listOf(stack[0], stack[1], stack[0]) + stack.dropCheck(2),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_VERIFY && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_VERIFY on an empty stack")
                head == OP_VERIFY && !castToBoolean(stack.first()) -> throw RuntimeException("OP_VERIFY failed")
                head == OP_VERIFY -> return run(
                    tail,
                    stack.tail(),
                    state.copy(opCount = state.opCount + 1),
                    signatureVersion
                )
                head == OP_WITHIN && stack.size < 3 -> throw RuntimeException("Cannot perform OP_WITHIN on a stack with less than 3 elements")
                head == OP_WITHIN -> {
                    val max = decodeNumber(stack[0])
                    val min = decodeNumber(stack[1])
                    val n = decodeNumber(stack[2])
                    val result = if (n in min until max) 1 else 0
                    return run(
                        tail,
                        listOf(encodeNumber(result)) + stack.dropCheck(3),
                        state.copy(opCount = state.opCount + 1),
                        signatureVersion
                    )
                }
                else -> {
                    throw RuntimeException("unexpected operator $head")
                }
            }
        }

        public fun verifyWitnessProgram(witness: ScriptWitness, witnessVersion: Long, program: ByteArray): Unit {
            val (stack, scriptPubKey) = when {
                witnessVersion == 0L && program.size == 20 -> {
                    // P2WPKH, program is simply the pubkey hash
                    require(witness.stack.count() == 2) { "Invalid witness program, should have 2 items" }
                    Pair(witness.stack, listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(program), OP_EQUALVERIFY, OP_CHECKSIG))

                }
                witnessVersion == 0L && program.size == 32 -> {
                    // P2WPSH, program is the hash of the script, and witness is the stack + the script
                    val check = Crypto.sha256(witness.stack.last())
                    require(check.contentEquals(program)) { "witness program mismatch" }
                    Pair(witness.stack.take(witness.stack.count() - 1), parse(witness.stack.last()))
                }
                witnessVersion == 0L -> throw IllegalArgumentException("Invalid witness program length: ${program.size}")
                (scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) != 0 -> throw IllegalArgumentException(
                    "Invalid witness version: ${witnessVersion}"
                )
                else -> {
                    // Higher version witness scripts return true for future softfork compatibility
                    return

                }
            }
            stack.forEach { require(it.size() <= MaxScriptElementSize) { "item is bigger than maximum push size" } }

            val stack1 = run(scriptPubKey, stack.toList().reversed(), signatureVersion = 1)
            require(stack1.size == 1)
            require(castToBoolean(stack1.first()))
        }

        public fun verifyScripts(scriptSig: ByteArray, scriptPubKey: ByteArray): Boolean =
            verifyScripts(scriptSig, scriptPubKey, ScriptWitness.empty)

        public fun verifyScripts(scriptSig: ByteVector, scriptPubKey: ByteVector, witness: ScriptWitness): Boolean =
            verifyScripts(scriptSig.toByteArray(), scriptPubKey.toByteArray(), witness)

        /**
         * verify a script sig/script pubkey pair:
         * <ul>
         * <li>parse and run script sig</li>
         * <li>parse and run script pubkey using the stack generated by the previous step</li>
         * <li>check the final stack</li>
         * <li>extract and run embedded pay2sh scripts if any and check the stack again</li>
         * </ul>
         *
         * @param scriptSig    signature script
         * @param scriptPubKey public key script
         * @return true if the scripts were successfully verified
         */
        public fun verifyScripts(scriptSig: ByteArray, scriptPubKey: ByteArray, witness: ScriptWitness): Boolean {
            fun checkStack(stack: List<ByteVector>): Boolean {
                return if (stack.isEmpty()) {
                    false
                } else if (!castToBoolean(stack.first())) {
                    false
                } else if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CLEANSTACK) != 0) {
                    if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_P2SH) == 0) throw RuntimeException("illegal script flag")
                    stack.size == 1
                } else true
            }

            if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_WITNESS) != 0) {
                // We can't check for correct unexpected witness data if P2SH was off, so require
                // that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
                // possible, which is not a softfork.
                require((scriptFlag and ScriptFlags.SCRIPT_VERIFY_P2SH) != 0)
            }
            val ssig = parse(scriptSig)
            if (((scriptFlag and ScriptFlags.SCRIPT_VERIFY_SIGPUSHONLY) != 0) && !isPushOnly(ssig)) throw RuntimeException(
                "signature script is not PUSH-only"
            )
            val stack = run(ssig, listOf(), signatureVersion = 0)

            val spub = parse(scriptPubKey)
            val stack0 = run(spub, stack, signatureVersion = 0)
            require(!stack0.isEmpty()) { "Script verification failed, stack should not be empty" }
            require(castToBoolean(stack0.first())) { "Script verification failed, stack starts with 'false'" }

            var hadWitness = false
            val stack1 = if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_WITNESS) != 0) {
                when {
                    spub.size == 2 && isSimpleValue(spub[0]) && spub[1] is OP_PUSHDATA -> {
                        val witnessVersion = simpleValue(spub[0])
                        val program = spub[1] as OP_PUSHDATA
                        when {
                            OP_PUSHDATA.isMinimal(
                                program.data.toByteArray(),
                                program.code
                            ) && program.data.size() in 2..40 -> {
                                hadWitness = true
                                require(ssig.isEmpty()) { "Malleated segwit script" }
                                verifyWitnessProgram(witness, witnessVersion.toLong(), program.data.toByteArray())
                                stack0.take(1)
                            }
                            else -> stack0
                        }
                    }
                    else -> stack0
                }
            } else stack0

            val stack2 = if (((scriptFlag and ScriptFlags.SCRIPT_VERIFY_P2SH) != 0) && isPayToScript(scriptPubKey)) {
                // scriptSig must be literals-only or validation fails
                if (!isPushOnly(ssig)) throw RuntimeException("signature script is not PUSH-only")

                // pay to script:
                // script sig is built as sig1 :: ... :: sigN :: serialized_script :: Nil
                // and script pubkey is HASH160 :: hash :: EQUAL :: Nil
                // if we got here after running script pubkey, it means that hash == HASH160(serialized script)
                // and stack would be serialized_script :: sigN :: ... :: sig1 :: Nil
                // we pop the first element of the stack, deserialize it and run it against the rest of the stack
                val stackp2sh = run(stack.first(), stack.tail(), 0)
                require(!stackp2sh.isEmpty()) { "Script verification failed, stack should not be empty" }
                require(castToBoolean(stackp2sh.first())) { "Script verification failed, stack starts with 'false'" }

                if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_WITNESS) != 0) {
                    val program = parse(stack.first())
                    when {
                        program.size == 2 && isSimpleValue(program[0]) && program[1] is OP_PUSHDATA && (program[1] as OP_PUSHDATA).data.size() in 2..32 -> {
                            hadWitness = true
                            val witnessVersion = simpleValue(program[0])
                            verifyWitnessProgram(
                                witness,
                                witnessVersion.toLong(),
                                (program[1] as OP_PUSHDATA).data.toByteArray()
                            )
                            stackp2sh.take(1)
                        }
                        else -> stackp2sh
                    }
                } else stackp2sh
            } else stack1

            if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_WITNESS) != 0 && !hadWitness) {
                require(witness.isNull())
            }
            return checkStack(stack2)
        }
    }
}
