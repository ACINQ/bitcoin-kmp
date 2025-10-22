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
import fr.acinq.secp256k1.Secp256k1
import kotlin.jvm.JvmStatic

public object Script {
    public const val MAX_SCRIPT_SIZE: Int = 10000
    public const val MAX_SCRIPT_ELEMENT_SIZE: Int = 520
    public const val MAX_OPS_PER_SCRIPT: Int = 201
    public const val MAX_STACK_SIZE: Int = 1000
    public const val LOCKTIME_THRESHOLD: Long = 500000000L
    public const val WITNESS_V0_SCRIPTHASH_SIZE: Int = 32
    public const val WITNESS_V0_KEYHASH_SIZE: Int = 20
    public const val WITNESS_V1_TAPROOT_SIZE: Int = 32
    public const val TAPROOT_LEAF_MASK: Int = 0xfe
    public const val TAPROOT_LEAF_TAPSCRIPT: Int = 0xc0

    // Validation weight per passing signature (Tapscript only, see BIP 342).
    public const val VALIDATION_WEIGHT_PER_SIGOP_PASSED: Int = 50

    // How much weight budget is added to the witness size (Tapscript only, see BIP 342).
    public const val VALIDATION_WEIGHT_OFFSET: Int = 50

    public val True: ByteVector = ByteVector("01")
    public val False: ByteVector = ByteVector.empty

    public fun isOpSuccess(opcode: Int): Boolean {
        return opcode == 80 || opcode == 98 || (opcode in 126..129) ||
                (opcode in 131..134) || (opcode in 137..138) ||
                (opcode in 141..142) || (opcode in 149..153) ||
                (opcode in 187..254)
    }

    public fun scriptIterator(script: ByteArray): Iterator<ScriptElt> = scriptIterator(ByteArrayInput(script))

    public fun scriptIterator(input: Input): Iterator<ScriptElt> {
        return object : Iterator<ScriptElt> {

            override fun hasNext(): Boolean = input.availableBytes > 0

            override fun next(): ScriptElt {
                val code = input.read()
                return when {
                    code == 0 -> OP_0
                    code in 1 until 0x4c -> OP_PUSHDATA(BtcSerializer.bytes(input, code), code)
                    code == 0x4c -> OP_PUSHDATA(BtcSerializer.bytes(input, BtcSerializer.uint8(input).toInt()), 0x4c)
                    code == 0x4d -> OP_PUSHDATA(BtcSerializer.bytes(input, BtcSerializer.uint16(input).toInt()), 0x4d)
                    code == 0x4e -> OP_PUSHDATA(BtcSerializer.bytes(input, BtcSerializer.uint32(input).toLong()), 0x4e)
                    ScriptEltMapping.code2elt.containsKey(code) -> ScriptEltMapping.code2elt.getValue(code)
                    else -> OP_INVALID(code)
                }
            }
        }
    }

    /**
     * parse a script from a input stream of binary data
     */
    @JvmStatic
    public fun parse(input: Input): List<ScriptElt> = scriptIterator(input).asSequence().toList()

    @JvmStatic
    public fun parse(blob: ByteArray): List<ScriptElt> = parse(ByteArrayInput(blob))

    @JvmStatic
    public fun parse(blob: ByteVector): List<ScriptElt> = parse(blob.toByteArray())

    @JvmStatic
    public fun parse(hex: String): List<ScriptElt> = parse(Hex.decode(hex))

    @JvmStatic
    public fun write(script: List<ScriptElt>, out: Output) {
        script.forEach { head ->
            when (head) {
                is OP_PUSHDATA -> {
                    when {
                        head.code < 0x4c -> {
                            require(head.data.size() == head.code)
                            out.write(head.data.size())
                        }

                        head.code == 0x4c -> {
                            require(head.data.size() <= 0xff)
                            BtcSerializer.writeUInt8(0x4Cu, out)
                            BtcSerializer.writeUInt8(head.data.size().toUByte(), out)
                        }

                        head.code == 0x4d -> {
                            require(head.data.size() <= 0xffff)
                            BtcSerializer.writeUInt8(0x4Du, out)
                            BtcSerializer.writeUInt16(head.data.size().toUShort(), out)
                        }

                        head.code == 0x4e -> {
                            require(head.data.size() <= 0xffffffff)
                            BtcSerializer.writeUInt8(0x4Eu, out)
                            BtcSerializer.writeUInt32(head.data.size().toUInt(), out)
                        }

                        else -> error("invalid OP_PUSHADATA opcode ${head.code}")
                    }
                    out.write(head.data.toByteArray())
                }

                else -> {
                    out.write(head.code)
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
        val value = if (op == OP_0) 0 else (op.code - 0x50)
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
        op.code > OP_16.code -> 1
        else -> 0
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
        return when {
            input.isEmpty() -> 0
            input.size > maximumSize -> throw RuntimeException("number cannot be encoded on more than $maximumSize bytes")
            else -> {
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
                if ((input.last().toInt() and 0x80) != 0)
                    -(result and (0x80L.shl(8 * (input.size - 1))).inv())
                else
                    result
            }
        }
    }

    @JvmStatic
    public fun decodeNumber(input: ByteVector, checkMinimalEncoding: Boolean, maximumSize: Int = 4): Long =
        decodeNumber(input.toByteArray(), checkMinimalEncoding, maximumSize)

    private fun castToBoolean(input: List<Byte>): Boolean {
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

    private fun castToBoolean(input: ByteArray): Boolean = castToBoolean(input.asList())

    private fun castToBoolean(input: ByteVector): Boolean = castToBoolean(input.toByteArray())

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
        script.size == 23 && script[0] == OP_HASH160.code.toByte() && script[1] == 0x14.toByte() && script[22] == OP_EQUAL.code.toByte()

    @JvmStatic
    public fun isNativeWitnessScript(script: List<ScriptElt>): Boolean = when {
        script.size != 2 -> false
        !setOf(OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16).contains(script[0]) -> false
        else -> when (val program = script[1]) {
            is OP_PUSHDATA -> program.data.size() in 2..40
            else -> false
        }
    }

    @JvmStatic
    public fun isNativeWitnessScript(script: ByteVector): Boolean = runCatching { parse(script) }.map { isNativeWitnessScript(it) }.getOrDefault(false)

    @JvmStatic
    public fun pushSize(op: ScriptElt): Int? = when (op) {
        is OP_PUSHDATA -> op.data.size()
        else -> null
    }

    @JvmStatic
    public fun getWitnessVersion(script: List<ScriptElt>): Int? = when {
        script.size != 2 -> null
        script[0] == OP_0 && (script[1].isPush(20) || script[1].isPush(32)) -> 0
        simpleValue(script[0]) in 1..16 && pushSize(script[1]) in 2..40 -> simpleValue(script[0]).toInt()
        else -> null
    }

    @JvmStatic
    public fun getWitnessVersion(script: ByteVector): Int? = runCatching { parse(script) }.map { getWitnessVersion(it) }.getOrDefault(null)

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
     * @param pubKeys are the public keys signatures will be checked against.
     * @param sigs    are the signatures for a subset of the public keys.
     * @return script witness for the pay-to-witness-script-hash script containing a multisig script.
     */
    @JvmStatic
    public fun witnessMultiSigMofN(pubKeys: List<PublicKey>, sigs: List<ByteVector>): ScriptWitness {
        val redeemScript = write(createMultiSigMofN(sigs.size, pubKeys))
        return ScriptWitness(listOf(ByteVector.empty) + sigs + listOf(ByteVector(redeemScript)))
    }

    @JvmStatic
    public fun isPay2pkh(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 5 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2].isPush(20) && script[3] == OP_EQUALVERIFY && script[4] == OP_CHECKSIG -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2pkh(script: ByteArray): Boolean = isPay2pkh(parse(script))

    @JvmStatic
    public fun isPay2sh(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 3 && script[0] == OP_HASH160 && script[1].isPush(20) && script[2] == OP_EQUAL -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2sh(script: ByteArray): Boolean = isPay2sh(parse(script))

    @JvmStatic
    public fun isPay2wpkh(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 2 && script[0] == OP_0 && script[1].isPush(20) -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2wpkh(script: ByteArray): Boolean = isPay2wpkh(parse(script))

    @JvmStatic
    public fun isPay2wsh(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 2 && script[0] == OP_0 && script[1].isPush(32) -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2wsh(script: ByteArray): Boolean = isPay2wsh(parse(script))

    @JvmStatic
    public fun isPay2tr(script: List<ScriptElt>): Boolean {
        return when {
            script.size == 2 && script[0] == OP_1 && script[1].isPush(32) -> true
            else -> false
        }
    }

    @JvmStatic
    public fun isPay2tr(script: ByteArray): Boolean = isPay2tr(parse(script))

    @JvmStatic
    public fun isPay2tr(script: ByteVector): Boolean = isPay2tr(script.toByteArray())

    /**
     * @param pubKeyHash public key hash
     * @return a pay-to-public-key-hash script
     */
    @JvmStatic
    public fun pay2pkh(pubKeyHash: ByteArray): List<ScriptElt> {
        require(pubKeyHash.size == 20) { "pubkey hash length must be 20 bytes" }
        return listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(pubKeyHash), OP_EQUALVERIFY, OP_CHECKSIG)
    }

    /**
     * @param pubKey public key
     * @return a pay-to-public-key-hash script
     */
    @JvmStatic
    public fun pay2pkh(pubKey: PublicKey): List<ScriptElt> = pay2pkh(pubKey.hash160())

    /**
     * @param script bitcoin script
     * @return a pay-to-script script
     */
    @JvmStatic
    public fun pay2sh(script: List<ScriptElt>): List<ScriptElt> = pay2sh(write(script))

    /**
     * @param script bitcoin script
     * @return a pay-to-script script
     */
    @JvmStatic
    public fun pay2sh(script: ByteArray): List<ScriptElt> = listOf(OP_HASH160, OP_PUSHDATA(Crypto.hash160(script)), OP_EQUAL)

    /**
     * @param script bitcoin script
     * @return a pay-to-witness-script script
     */
    @JvmStatic
    public fun pay2wsh(script: List<ScriptElt>): List<ScriptElt> = pay2wsh(write(script))

    /**
     * @param script bitcoin script
     * @return a pay-to-witness-script script
     */
    @JvmStatic
    public fun pay2wsh(script: ByteArray): List<ScriptElt> = listOf(OP_0, OP_PUSHDATA(Crypto.sha256(script)))

    /**
     * @param script bitcoin script
     * @return a pay-to-witness-script script
     */
    @JvmStatic
    public fun pay2wsh(script: ByteVector): List<ScriptElt> = pay2wsh(script.toByteArray())

    /**
     * @param pubKeyHash public key hash
     * @return a pay-to-witness-public-key-hash script
     */
    @JvmStatic
    public fun pay2wpkh(pubKeyHash: ByteArray): List<ScriptElt> {
        require(pubKeyHash.size == 20) { "pubkey hash length must be 20 bytes" }
        return listOf(OP_0, OP_PUSHDATA(pubKeyHash))
    }

    /**
     * @param pubKey public key
     * @return a pay-to-witness-public-key-hash script
     */
    @JvmStatic
    public fun pay2wpkh(pubKey: PublicKey): List<ScriptElt> = pay2wpkh(pubKey.hash160())

    /**
     * @param pubKey public key
     * @param sig signature matching the public key
     * @return script witness for the corresponding pay-to-witness-public-key-hash script
     */
    @JvmStatic
    public fun witnessPay2wpkh(pubKey: PublicKey, sig: ByteVector): ScriptWitness = ScriptWitness(listOf(sig, pubKey.value))

    /**
     * @param outputKey public key exposed by the taproot script (tweaked based on the tapscripts).
     * @return a pay-to-taproot script.
     */
    @JvmStatic
    public fun pay2tr(outputKey: XonlyPublicKey): List<ScriptElt> = listOf(OP_1, OP_PUSHDATA(outputKey.value))

    /**
     * @param internalKey internal public key that will be tweaked with the [scripts] provided.
     * @param scripts optional spending scripts that can be used instead of key-path spending.
     */
    @JvmStatic
    public fun pay2tr(internalKey: XonlyPublicKey, scripts: ScriptTree?): List<ScriptElt> = pay2tr(internalKey, scripts?.hash())

    /**
     * @param internalKey internal public key that will be tweaked with the [scriptsRoot] provided.
     * @param scriptsRoot optional merkle root of the spending scripts that can be used instead of key-path spending.
     */
    @JvmStatic
    public fun pay2tr(internalKey: XonlyPublicKey, scriptsRoot: ByteVector32?): List<ScriptElt> {
        val tweak = when (scriptsRoot) {
            null -> Crypto.TaprootTweak.NoScriptTweak
            else -> Crypto.TaprootTweak.ScriptTweak(scriptsRoot)
        }
        val (publicKey, _) = internalKey.outputKey(tweak)
        return pay2tr(publicKey)
    }

    /** NB: callers must ensure that they use the correct [Crypto.TaprootTweak] when generating their signature. */
    @JvmStatic
    public fun witnessKeyPathPay2tr(sig: ByteVector64, sighash: Int = SigHash.SIGHASH_DEFAULT): ScriptWitness = when (sighash) {
        SigHash.SIGHASH_DEFAULT -> ScriptWitness(listOf(sig))
        else -> ScriptWitness(listOf(sig.concat(sighash.toByte())))
    }

    /**
     * @param internalKey taproot internal public key.
     * @param script script that is spent (must exist in the [scriptTree]).
     * @param witness witness for the spent [script].
     * @param scriptTree tapscript tree.
     */
    @JvmStatic
    public fun witnessScriptPathPay2tr(internalKey: XonlyPublicKey, script: ScriptTree.Leaf, witness: ScriptWitness, scriptTree: ScriptTree): ScriptWitness {
        val controlBlock = ControlBlock.build(internalKey, scriptTree, script)
        return ScriptWitness(witness.stack + script.script + controlBlock)
    }

    /** Standard P2A (pay-to-anchor) output. */
    @JvmStatic
    public val pay2anchor: List<ScriptElt> = listOf(OP_1, OP_PUSHDATA(ByteVector("4e73")))

    /** An empty witness script is used to spend [pay2anchor] outputs. */
    @JvmStatic
    public val witnessPay2anchor: ScriptWitness = ScriptWitness.empty

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
        if (!((tx.lockTime < Transaction.LOCKTIME_THRESHOLD && lockTime < Transaction.LOCKTIME_THRESHOLD) || (tx.lockTime >= Transaction.LOCKTIME_THRESHOLD && lockTime >= Transaction.LOCKTIME_THRESHOLD))) {
            return false
        }

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
        if (!((txToSequenceMasked < TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked < TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG) || (txToSequenceMasked >= TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG))) {
            return false
        }

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nSequenceMasked > txToSequenceMasked)
            return false

        return true
    }

    public fun sigHashType(sig: ByteArray): Int = when {
        sig.size == 64 -> SigHash.SIGHASH_DEFAULT
        sig.size == 65 && sig[64].toInt() == SigHash.SIGHASH_DEFAULT -> error("invalid sig hashtype")
        sig.size == 65 -> sig[64].toInt() and 0xff
        else -> error("invalid signature")
    }

    public fun sigHashType(sig: ByteVector): Int = sigHashType(sig.toByteArray())

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
    public data class Context(val tx: Transaction, val inputIndex: Int, val amount: Satoshi, val prevouts: List<TxOut>) {
        internal var executionData: ExecutionData = ExecutionData.empty

        init {
            require(inputIndex >= 0 && inputIndex < tx.txIn.count()) { "invalid input index" }
        }
    }

    public data class ExecutionData(val annex: ByteVector?, val tapleafHash: ByteVector32?, val validationWeightLeft: Int? = null, val codeSeparatorPos: Long = 0xFFFFFFFFL) {
        public companion object {
            public val empty: ExecutionData = ExecutionData(null, null, null, 0xFFFFFFFFL)
        }
    }

    public object ControlBlock {
        /**
         * Build a control block to add to the witness of a taproot transaction when spending with the script path.
         * It includes information to re-compute the merkle root from the script you are using.
         *
         * For example, suppose you have the following script tree:
         *     root
         *     /   \
         *    /  \   #3
         *   #1  #2
         *
         * To recompute its merkle root you need to provide either:
         *  - if you're spending with script #1: leaves #2 and #3
         *  - if you're spending with script #2: leaves #1 and #3
         *  - if you're spending with script #3: branch(#1, #2)
         *
         * @param internalPubKey internal public key.
         * @param scriptTree tapscript tree.
         * @param spendingScript script leaf we're spending (must exist in the [scriptTree]).
         */
        @JvmStatic
        public fun build(internalPubKey: XonlyPublicKey, scriptTree: ScriptTree, spendingScript: ScriptTree.Leaf): ByteVector {
            val merkleProof = scriptTree.merkleProof(spendingScript.hash())
            require(merkleProof != null) { "cannot build control block: the spending script leaf cannot be found in the script tree provided" }
            return build(internalPubKey, scriptTree.hash(), merkleProof, spendingScript.leafVersion)
        }

        /**
         * @param internalPubKey internal public key.
         * @param merkleRoot merkle root of the tapscript tree.
         * @param merkleProof merkle proof of the spent script leaf: must not contain the script leaf nor the merkle root.
         * @param leafVersion script version of the spent script leaf.
         */
        @JvmStatic
        public fun build(internalPubKey: XonlyPublicKey, merkleRoot: ByteVector32, merkleProof: ByteArray, leafVersion: Int): ByteVector {
            val (_, parity) = internalPubKey.outputKey(merkleRoot)
            val controlByte = (leafVersion + (if (parity) 1 else 0)).toByte()
            return ByteVector.empty.concat(controlByte).concat(internalPubKey.value).concat(merkleProof)
        }
    }

    public class Runner(
        public val context: Context,
        public val scriptFlag: Int = ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS,
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

        public fun checkSignatureEcdsa(pubKey: ByteArray, sigBytes: ByteArray, scriptCode: ByteArray, signatureVersion: Int): Boolean {
            return when {
                sigBytes.isEmpty() -> false
                !Crypto.checkSignatureEncoding(sigBytes, scriptFlag) -> throw RuntimeException("invalid signature encoding")
                !Crypto.checkPubKeyEncoding(pubKey, scriptFlag, signatureVersion) -> throw RuntimeException("invalid public key encoding")
                !Crypto.isPubKeyValid(pubKey) -> false // see how this is different from above ?
                else -> {
                    val sigHashFlags = sigBytes.last().toInt() and 0xff
                    // sig hash is the last byte
                    val sigBytes1 = sigBytes.dropLast(1).toByteArray() // drop sig hash
                    if (sigBytes1.isEmpty()) false
                    else {
                        val hash = Transaction.hashForSigning(context.tx, context.inputIndex, scriptCode, sigHashFlags, context.amount, signatureVersion)
                        // signature is normalized here, but high-S correctness has already been checked
                        val normalized = Crypto.normalize(sigBytes1).first
                        val pub = PublicKey.parse(pubKey)
                        val result = Crypto.verifySignature(hash, normalized, pub)
                        result
                    }
                }
            }
        }

        public fun checkSignatureSchnorr(pubKey: ByteArray, sigBytes: ByteArray, signatureVersion: Int): Boolean {
            require(signatureVersion == SigVersion.SIGVERSION_TAPSCRIPT)
            if (sigBytes.isNotEmpty()) {
                require(context.executionData.validationWeightLeft != null)
                context.executionData.validationWeightLeft?.let {
                    val weightLeft = it - VALIDATION_WEIGHT_PER_SIGOP_PASSED
                    context.executionData = context.executionData.copy(validationWeightLeft = weightLeft)
                    require(weightLeft >= 0) { "tapscript weight validation failed" }
                }
            }
            return when {
                pubKey.isEmpty() -> error("invalid pubkey")
                pubKey.size == 32 && sigBytes.isEmpty() -> false
                pubKey.size == 32 -> {
                    val sighashType = sigHashType(sigBytes)
                    val hash = Transaction.hashForSigningSchnorr(
                        context.tx,
                        context.inputIndex,
                        context.prevouts,
                        sighashType,
                        signatureVersion,
                        context.executionData.tapleafHash,
                        context.executionData.annex,
                        context.executionData.codeSeparatorPos
                    )
                    val result = Secp256k1.verifySchnorr(sigBytes.take(64).toByteArray(), hash.toByteArray(), pubKey)
                    require(result) { "Invalid Schnorr signature" }
                    result
                }

                else -> {
                    require((scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE) == 0) { "invalid pubkey type" }
                    sigBytes.isNotEmpty()
                }
            }
        }

        /**
         * @param pubKey public key
         * @param sigBytes signature, in Bitcoin format (DER encoded + 1 trailing sighash bytes)
         * @param scriptCode current script code
         * @param signatureVersion version (legacy or segwit)
         * @return true if the signature is valid
         */
        public fun checkSignature(pubKey: ByteArray, sigBytes: ByteArray, scriptCode: ByteArray, signatureVersion: Int): Boolean {
            return when (signatureVersion) {
                SigVersion.SIGVERSION_BASE, SigVersion.SIGVERSION_WITNESS_V0 -> checkSignatureEcdsa(pubKey, sigBytes, scriptCode, signatureVersion)
                SigVersion.SIGVERSION_TAPROOT -> false // Key path spending in Taproot has no script, so this is unreachable.
                SigVersion.SIGVERSION_TAPSCRIPT -> checkSignatureSchnorr(pubKey, sigBytes, signatureVersion)
                else -> error("invalid signature version")
            }
        }

        public fun checkSignature(pubKey: ByteVector, sigBytes: ByteVector, scriptCode: ByteVector, signatureVersion: Int): Boolean =
            checkSignature(pubKey.toByteArray(), sigBytes.toByteArray(), scriptCode.toByteArray(), signatureVersion)

        public tailrec fun checkSignatures(pubKeys: List<ByteVector>, sigs: List<ByteVector>, scriptCode: ByteVector, signatureVersion: Int): Boolean {
            return when {
                sigs.isEmpty() -> true
                sigs.count() > pubKeys.count() -> false
                !Crypto.checkSignatureEncoding(sigs.first().toByteArray(), scriptFlag) -> throw RuntimeException("invalid signature")
                checkSignature(pubKeys.first(), sigs.first(), scriptCode, signatureVersion) -> checkSignatures(pubKeys.tail(), sigs.tail(), scriptCode, signatureVersion)
                else -> checkSignatures(pubKeys.tail(), sigs, scriptCode, signatureVersion)
            }
        }

        public fun checkMinimalEncoding(): Boolean = (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALDATA) != 0

        public fun decodeNumber(input: ByteVector, maximumSize: Int = 4): Long =
            decodeNumber(input.toByteArray(), checkMinimalEncoding(), maximumSize)

        public fun decodeNumber(input: ByteArray, maximumSize: Int = 4): Long =
            decodeNumber(input, checkMinimalEncoding(), maximumSize)

        public fun run(script: ByteArray, signatureVersion: Int): List<ByteVector> {
            return run(script, listOf(), signatureVersion)
        }

        public fun run(script: List<ScriptElt>, signatureVersion: Int): List<ByteVector> =
            run(script, listOf(), signatureVersion)

        public fun run(script: ByteArray, stack: List<ByteVector>, signatureVersion: Int): List<ByteVector> {
            if (signatureVersion == SigVersion.SIGVERSION_BASE || signatureVersion == SigVersion.SIGVERSION_WITNESS_V0) {
                require(script.size <= MAX_SCRIPT_SIZE) { "Script is too large" }
            }
            return run(parse(script), stack, signatureVersion)
        }

        public fun run(script: ByteVector, stack: List<ByteVector>, signatureVersion: Int): List<ByteVector> =
            run(script.toByteArray(), stack, signatureVersion)

        public fun run(
            script: List<ScriptElt>,
            stack: List<ByteVector>,
            signatureVersion: Int
        ): List<ByteVector> {
            stack.forEach { require(it.size() <= MAX_SCRIPT_ELEMENT_SIZE) { "item is bigger than maximum push size" } }
            return runInternal(script, stack, signatureVersion)
        }

        /**
         * internal script execution loop.
         */
        private fun runInternal(
            script: List<ScriptElt>,
            inputStack: List<ByteVector>,
            signatureVersion: Int
        ): List<ByteVector> {
            val stack = inputStack.toMutableList()
            val altstack = mutableListOf<ByteVector>()
            // conditions is a stack of boolean that is checked by each IF/NOTIF instruction
            // each time we execute IF/NOTIF, we insert the boolean that is checked by IF/NOTIF into our "conditions" stack
            // each time we execute ELSE, we flip the head our "conditions" stack
            // and each time we execute ENDIF we remove the head of our "conditions" stack
            // if any value in our "conditions" stack is false, it means that we're in an IF branch that is not executed
            // OP_1 // conditions = []
            // OP_IF
            //   OP_CHECKSIG // conditions = [true]
            //   OP_IF //
            //     OP_2 // conditions = [false, true] (we assume CHECKSIG failed), this branch will not be executed
            //   OP_ELSE
            //     OP_3 // conditions = [true, true]
            // OP_ELSE
            //   OP_PUSHDATA("deadbeef") // conditions = [false], this branch will not be executed
            // OP_ENDIF
            // OP_CHECKSIG // conditions = []
            val conditions = mutableListOf<Boolean>()
            var opCount = 0
            var scriptCode: List<ScriptElt> = script

            for (currentPos in script.indices) {
                val op = script[currentPos]
                if (isDisabled(op)) throw RuntimeException("$op is disabled")
                if (signatureVersion == SigVersion.SIGVERSION_BASE || signatureVersion == SigVersion.SIGVERSION_WITNESS_V0) {
                    // Note how OP_RESERVED does not count towards the opcode limit.
                    opCount += cost(op)
                    require(opCount <= MAX_OPS_PER_SCRIPT) { "Operation limit exceeded" }
                }

                when {
                    op == OP_CODESEPARATOR && signatureVersion == SigVersion.SIGVERSION_BASE && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0 -> throw RuntimeException("Using OP_CODESEPARATOR in non-witness script")
                    op == OP_VERIF -> throw RuntimeException("OP_VERIF is always invalid")
                    op == OP_VERNOTIF -> throw RuntimeException("OP_VERNOTIF is always invalid")
                    op is OP_PUSHDATA && op.data.size() > MAX_SCRIPT_ELEMENT_SIZE -> throw RuntimeException("Push value size limit exceeded")
                    // check whether we are in a non-executed IF branch
                    op == OP_IF && conditions.any { !it } -> {
                        conditions.add(0, false)
                    }

                    op == OP_IF && stack.isEmpty() -> throw RuntimeException("Invalid OP_IF construction")
                    op == OP_IF -> {
                        val stackhead = stack.removeFirst()
                        when {
                            stackhead == True && signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 -> conditions.add(0, true)
                            stackhead == False && signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 -> conditions.add(0, false)
                            signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 -> throw RuntimeException("OP_IF argument must be minimal")
                            signatureVersion == SigVersion.SIGVERSION_TAPSCRIPT && stackhead != True && stackhead != False -> throw RuntimeException("OP_IF argument must be minimal")
                            castToBoolean(stackhead) -> conditions.add(0, true)
                            else -> conditions.add(0, false)
                        }
                    }

                    op == OP_NOTIF && conditions.any { !it } -> {
                        conditions.add(0, true)
                    }

                    op == OP_NOTIF && stack.isEmpty() -> throw RuntimeException("Invalid OP_NOTIF construction")
                    op == OP_NOTIF -> {
                        val stackhead = stack.removeFirst()
                        when {
                            stackhead == False && signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 -> conditions.add(0, true)
                            stackhead == True && signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 -> conditions.add(0, false)
                            signatureVersion == SigVersion.SIGVERSION_WITNESS_V0 && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALIF) != 0 -> throw RuntimeException("OP_NOTIF argument must be minimal")
                            signatureVersion == SigVersion.SIGVERSION_TAPSCRIPT && stackhead != True && stackhead != False -> throw RuntimeException("OP_IF argument must be minimal")
                            castToBoolean(stackhead) -> conditions.add(0, false)
                            else -> conditions.add(0, true)
                        }
                    }

                    op == OP_ELSE && conditions.isEmpty() -> throw RuntimeException("Invalid OP_ELSE construction")
                    op == OP_ELSE -> {
                        conditions[0] = !conditions[0]
                    }

                    op == OP_ENDIF && conditions.isEmpty() -> throw RuntimeException("Invalid OP_ENDIF construction")
                    op == OP_ENDIF -> {
                        conditions.removeFirst()
                    }

                    conditions.any { !it } -> {} // do nothing, we're in an IF branch that is not executed

                    // and now, things that are checked only in an executed IF branch
                    op == OP_0 -> stack.add(0, False)
                    isSimpleValue(op) -> stack.add(0, encodeNumber(simpleValue(op).toInt()))
                    op == OP_NOP -> {}

                    isUpgradableNop(op) && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0) -> throw RuntimeException("use of upgradable NOP is discouraged")
                    isUpgradableNop(op) -> {}

                    op == OP_1ADD && stack.isEmpty() -> throw RuntimeException("cannot run OP_1ADD on an empty stack")
                    op == OP_1ADD -> {
                        stack[0] = encodeNumber(decodeNumber(stack.first()) + 1)
                    }

                    op == OP_1SUB && stack.isEmpty() -> throw RuntimeException("cannot run OP_1SUB on an empty stack")
                    op == OP_1SUB -> {
                        stack[0] = encodeNumber(decodeNumber(stack.first()) - 1)
                    }

                    op == OP_ABS && stack.isEmpty() -> throw RuntimeException("cannot run OP_ABS on an empty stack")
                    op == OP_ABS -> {
                        stack[0] = encodeNumber(kotlin.math.abs(decodeNumber(stack.first())))
                    }

                    op == OP_ADD && stack.size < 2 -> throw RuntimeException("cannot run OP_ADD on a stack with less than 2 elements")
                    op == OP_ADD -> {
                        val x = decodeNumber(stack.removeFirst())
                        val y = decodeNumber(stack.removeFirst())
                        val result = x + y
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_BOOLAND && stack.size < 2 -> throw RuntimeException("cannot run OP_BOOLAND on a stack with less than 2 elements")
                    op == OP_BOOLAND -> {
                        val x = decodeNumber(stack.removeFirst())
                        val y = decodeNumber(stack.removeFirst())
                        val result = if (x != 0L && y != 0L) 1L else 0L
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_BOOLOR && stack.size < 2 -> throw RuntimeException("cannot run OP_BOOLOR on a stack with less than 2 elements")
                    op == OP_BOOLOR -> {
                        val x = decodeNumber(stack.removeFirst())
                        val y = decodeNumber(stack.removeFirst())
                        val result = if (x != 0L || y != 0L) 1L else 0L
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_CHECKLOCKTIMEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) != 0) && stack.isEmpty() -> throw RuntimeException("cannot run OP_CHECKLOCKTIMEVERIFY on an empty stack")
                    op == OP_CHECKLOCKTIMEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) != 0) -> {
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
                        if (!checkLockTime(locktime, context.tx, context.inputIndex)) throw RuntimeException("unsatisfied CLTV lock time")
                    }

                    op == OP_CHECKLOCKTIMEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0) -> throw RuntimeException("use of upgradable NOP is discouraged")
                    op == OP_CHECKLOCKTIMEVERIFY -> {}

                    op == OP_CHECKSEQUENCEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) != 0) && stack.isEmpty() -> throw RuntimeException("cannot run OP_CHECKSEQUENCEVERIFY on an empty stack")
                    op == OP_CHECKSEQUENCEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) != 0) -> {
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
                        if ((sequence and TxIn.SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0L) {
                            // Actually compare the specified inverse sequence number
                            // with the input.
                            if (!checkSequence(sequence, context.tx, context.inputIndex)) throw RuntimeException("unsatisfied CSV lock time")
                        }
                    }

                    op == OP_CHECKSEQUENCEVERIFY && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) != 0) -> throw RuntimeException("use of upgradable NOP is discouraged")
                    op == OP_CHECKSEQUENCEVERIFY -> {}

                    op == OP_CHECKSIG && stack.size < 2 -> throw RuntimeException("Cannot perform OP_CHECKSIG on a stack with less than 2 elements")
                    op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY -> {
                        val pubKey = stack.removeFirst()
                        val sigBytes = stack.removeFirst()
                        // remove signature from script
                        val scriptCode1 = if (signatureVersion == SigVersion.SIGVERSION_BASE) {
                            val scriptCode1 = removeSignature(scriptCode, sigBytes)
                            if (scriptCode1.size != scriptCode.size && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0) {
                                throw RuntimeException("Signature is found in scriptCode")
                            }
                            scriptCode1
                        } else {
                            scriptCode
                        }
                        val success = checkSignature(pubKey.toByteArray(), sigBytes.toByteArray(), write(scriptCode1), signatureVersion)
                        if (!success && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_NULLFAIL) != 0) {
                            require(sigBytes.isEmpty()) { "Signature must be zero for failed CHECKSIG operation" }
                        }
                        if (op == OP_CHECKSIGVERIFY) {
                            require(success) { "OP_CHECKSIGVERIFY failed" }
                        } else {
                            stack.add(0, if (success) True else False)
                        }
                    }

                    op == OP_CHECKSIGADD -> {
                        // OP_CHECKSIGADD is only available in Tapscript
                        require(signatureVersion != SigVersion.SIGVERSION_BASE && signatureVersion != SigVersion.SIGVERSION_WITNESS_V0) { "invalid opcode" }
                        require(stack.size >= 3) { "Cannot perform OP_CHECKSIGADD on a stack with less than 3 elements" }
                        val pubKey = stack.removeFirst()
                        val num = decodeNumber(stack.removeFirst())
                        val sigBytes = stack.removeFirst()
                        val success = checkSignature(pubKey.toByteArray(), sigBytes.toByteArray(), write(scriptCode), signatureVersion)
                        stack.add(0, encodeNumber(num + (if (success) 1 else 0)))
                    }

                    op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY -> {
                        require(signatureVersion != SigVersion.SIGVERSION_TAPSCRIPT) { "invalid OP_CHECKMULTISIG operation" }
                        // pop public keys
                        val m = decodeNumber(stack.removeFirst()).toInt()
                        if (m < 0 || m > 20) throw RuntimeException("OP_CHECKMULTISIG: invalid number of public keys")
                        opCount += m
                        if (opCount > MAX_OPS_PER_SCRIPT) throw RuntimeException("operation count is over the limit")
                        val pubKeys = (1..m).map { stack.removeFirst() }

                        // pop signatures
                        val n = decodeNumber(stack.removeFirst()).toInt()
                        if (n < 0 || n > m) throw RuntimeException("OP_CHECKMULTISIG: invalid number of signatures")
                        // check that we have at least n + 1 items on the stack (+1 because of a bug in the reference client)
                        require(stack.size >= n + 1) { "invalid stack operation" }
                        val sigs = (1..n).map { stack.removeFirst() }
                        if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_NULLDUMMY) != 0) require(stack.first().size() == 0) { "multisig dummy is not empty" }
                        stack.removeFirst()

                        // Drop the signature in pre-segwit scripts but not segwit scripts
                        val scriptCode1 = if (signatureVersion == SigVersion.SIGVERSION_BASE) {
                            val scriptCode1 = removeSignatures(scriptCode, sigs)
                            if (scriptCode1.size != scriptCode.size && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_CONST_SCRIPTCODE) != 0) {
                                throw RuntimeException("Signature is found in scriptCode")
                            }
                            scriptCode1
                        } else {
                            scriptCode
                        }
                        val success = checkSignatures(pubKeys, sigs, write(scriptCode1).byteVector(), signatureVersion)
                        if (!success && (scriptFlag and ScriptFlags.SCRIPT_VERIFY_NULLFAIL) != 0) {
                            sigs.forEach { require(it.isEmpty()) { "Signature must be zero for failed CHECKMULTISIG operation" } }
                        }
                        if (op == OP_CHECKMULTISIGVERIFY) {
                            require(success) { "OP_CHECKMULTISIGVERIFY failed" }
                        } else {
                            stack.add(0, if (success) True else False)
                        }
                    }

                    op == OP_CODESEPARATOR -> {
                        this.context.executionData = this.context.executionData.copy(codeSeparatorPos = currentPos.toLong())
                        scriptCode = script.drop(currentPos + 1)
                    }

                    op == OP_DEPTH -> {
                        stack.add(0, encodeNumber(stack.size))
                    }

                    op == OP_SIZE && stack.isEmpty() -> throw RuntimeException("Cannot run OP_SIZE on an empty stack")
                    op == OP_SIZE -> {
                        stack.add(0, encodeNumber(stack.first().size()))
                    }

                    op == OP_DROP -> {
                        stack.removeFirst()
                    }

                    op == OP_2DROP -> {
                        stack.removeFirst()
                        stack.removeFirst()
                    }

                    op == OP_DUP -> {
                        stack.add(0, stack.first())
                    }

                    op == OP_2DUP && stack.size < 2 -> throw RuntimeException("Cannot perform OP_2DUP on a stack with less than 2 elements")
                    op == OP_2DUP -> {
                        val x1 = stack[0]
                        val x2 = stack[1]
                        stack.addAll(0, listOf(x1, x2))
                    }

                    op == OP_3DUP && stack.size < 3 -> throw RuntimeException("Cannot perform OP_3DUP on a stack with less than 2 elements")
                    op == OP_3DUP -> {
                        val x1 = stack[0]
                        val x2 = stack[1]
                        val x3 = stack[2]
                        stack.addAll(0, listOf(x1, x2, x3))
                    }

                    op == OP_EQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_EQUAL on a stack with less than 2 elements")
                    op == OP_EQUAL -> {
                        val x1 = stack.removeFirst()
                        val x2 = stack.removeFirst()
                        stack.add(0, if (x1 != x2) False else True)
                    }

                    op == OP_EQUALVERIFY && stack.size < 2 -> throw RuntimeException("Cannot perform OP_EQUALVERIFY on a stack with less than 2 elements")
                    op == OP_EQUALVERIFY -> {
                        val x1 = stack.removeFirst()
                        val x2 = stack.removeFirst()
                        require(x1 == x2) { "OP_EQUALVERIFY failed: elements are different" }
                    }

                    op == OP_FROMALTSTACK -> {
                        stack.add(0, altstack.removeFirst())
                    }

                    op == OP_HASH160 -> {
                        stack[0] = Crypto.hash160(stack.first()).byteVector()
                    }

                    op == OP_HASH256 -> {
                        stack[0] = Crypto.hash256(stack.first()).byteVector()
                    }

                    op == OP_IFDUP && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_IFDUP on an empty stack")
                    op == OP_IFDUP -> {
                        if (castToBoolean(stack.first())) stack.add(0, stack.first())
                    }

                    op == OP_LESSTHAN && stack.size < 2 -> throw RuntimeException("Cannot perform OP_LESSTHAN on a stack with less than 2 elements")
                    op == OP_LESSTHAN -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = if (x2 < x1) 1 else 0
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_LESSTHANOREQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_LESSTHANOREQUAL on a stack with less than 2 elements")
                    op == OP_LESSTHANOREQUAL -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = if (x2 <= x1) 1 else 0
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_GREATERTHAN && stack.size < 2 -> throw RuntimeException("Cannot perform OP_GREATERTHAN on a stack with less than 2 elements")
                    op == OP_GREATERTHAN -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = if (x2 > x1) 1 else 0
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_GREATERTHANOREQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_GREATERTHANOREQUAL on a stack with less than 2 elements")
                    op == OP_GREATERTHANOREQUAL -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = if (x2 >= x1) 1 else 0
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_MAX && stack.size < 2 -> throw RuntimeException("Cannot perform OP_MAX on a stack with less than 2 elements")
                    op == OP_MAX -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = if (x2 > x1) x2 else x1
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_MIN && stack.size < 2 -> throw RuntimeException("Cannot perform OP_MIN on a stack with less than 2 elements")
                    op == OP_MIN -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = if (x2 < x1) x2 else x1
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_NEGATE && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_NEGATE on an empty stack")
                    op == OP_NEGATE -> {
                        stack[0] = encodeNumber(-decodeNumber(stack.first()))
                    }

                    op == OP_NIP && stack.size < 2 -> throw RuntimeException("Cannot perform OP_NIP on a stack with less than 2 elements")
                    op == OP_NIP -> {
                        stack.removeAt(1)
                    }

                    op == OP_NOT && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_NOT on an empty stack")
                    op == OP_NOT -> {
                        stack[0] = encodeNumber(if (decodeNumber(stack.first()) == 0L) 1 else 0)
                    }

                    op == OP_0NOTEQUAL && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_0NOTEQUAL on an empty stack")
                    op == OP_0NOTEQUAL -> {
                        stack[0] = encodeNumber(if (decodeNumber(stack.first()) == 0L) 0 else 1)
                    }

                    op == OP_NUMEQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_NUMEQUAL on a stack with less than 2 elements")
                    op == OP_NUMEQUAL -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = if (x1 == x2) 1 else 0
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_NUMEQUALVERIFY && stack.size < 2 -> throw RuntimeException("Cannot perform OP_NUMEQUALVERIFY on a stack with less than 2 elements")
                    op == OP_NUMEQUALVERIFY -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        require(x1 == x2) { "OP_NUMEQUALVERIFY failed" }
                    }

                    op == OP_NUMNOTEQUAL && stack.size < 2 -> throw RuntimeException("Cannot perform OP_NUMNOTEQUAL on a stack with less than 2 elements")
                    op == OP_NUMNOTEQUAL -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = if (x1 != x2) 1 else 0
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_OVER && stack.size < 2 -> throw RuntimeException("Cannot perform OP_OVER on a stack with less than 2 elements")
                    op == OP_OVER -> {
                        stack.add(0, stack[1])
                    }

                    op == OP_2OVER && stack.size < 4 -> throw RuntimeException("Cannot perform OP_2OVER on a stack with less than 2 elements")
                    op == OP_2OVER -> {
                        stack.addAll(0, listOf(stack[2], stack[3]))
                    }

                    op == OP_PICK && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_PICK on an empty stack")
                    op == OP_PICK -> {
                        val n = decodeNumber(stack.removeFirst()).toInt()
                        require(stack.size > n) { "Cannot perform OP_PICK on a stack with less than ${n + 1} elements" }
                        stack.add(0, stack[n])
                    }

                    op is OP_PUSHDATA && ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_MINIMALDATA) != 0) && !OP_PUSHDATA.isMinimal(op.data.toByteArray(), op.code) -> throw RuntimeException("not minimal push")
                    op is OP_PUSHDATA -> stack.add(0, op.data)

                    op == OP_ROLL && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_ROLL on an empty stack")
                    op == OP_ROLL -> {
                        val n = decodeNumber(stack.removeFirst()).toInt()
                        require(stack.size > n) { "Cannot perform OP_ROLL on a stack with less than ${n + 1} elements" }
                        val xn = stack.removeAt(n)
                        stack.add(0, xn)
                    }

                    op == OP_ROT && stack.size < 3 -> throw RuntimeException("Cannot perform OP_ROT on a stack with less than 3 elements")
                    op == OP_ROT -> {
                        val x0 = stack[0]
                        val x1 = stack[1]
                        val x2 = stack[2]
                        stack[0] = x2
                        stack[1] = x0
                        stack[2] = x1
                    }

                    op == OP_2ROT && stack.size < 6 -> throw RuntimeException("Cannot perform OP_2ROT on a stack with less than 6 elements")
                    op == OP_2ROT -> {
                        val x0 = stack[0]
                        val x1 = stack[1]
                        val x2 = stack[2]
                        val x3 = stack[3]
                        val x4 = stack[4]
                        val x5 = stack[5]
                        stack[0] = x4
                        stack[1] = x5
                        stack[2] = x0
                        stack[3] = x1
                        stack[4] = x2
                        stack[5] = x3
                    }

                    op == OP_RIPEMD160 -> {
                        stack[0] = Crypto.ripemd160(stack.first()).byteVector()
                    }

                    op == OP_SHA1 -> {
                        stack[0] = Crypto.sha1(stack.first()).byteVector()
                    }

                    op == OP_SHA256 -> {
                        stack[0] = Crypto.sha256(stack.first()).byteVector()
                    }

                    op == OP_SUB && stack.size < 2 -> throw RuntimeException("Cannot perform OP_SUB on a stack with less than 2 elements")
                    op == OP_SUB -> {
                        val x1 = decodeNumber(stack.removeFirst())
                        val x2 = decodeNumber(stack.removeFirst())
                        val result = x2 - x1
                        stack.add(0, encodeNumber(result))
                    }

                    op == OP_SWAP && stack.size < 2 -> throw RuntimeException("Cannot perform OP_SWAP on a stack with less than 2 elements")
                    op == OP_SWAP -> {
                        val x0 = stack[0]
                        val x1 = stack[1]
                        stack[0] = x1
                        stack[1] = x0
                    }

                    op == OP_2SWAP && stack.size < 4 -> throw RuntimeException("Cannot perform OP_2SWAP on a stack with less than 4 elements")
                    op == OP_2SWAP -> {
                        val x0 = stack[0]
                        val x1 = stack[1]
                        val x2 = stack[2]
                        val x3 = stack[3]
                        stack[0] = x2
                        stack[1] = x3
                        stack[2] = x0
                        stack[3] = x1
                    }

                    op == OP_TOALTSTACK -> {
                        altstack.add(0, stack.removeFirst())
                    }

                    op == OP_TUCK && stack.size < 2 -> throw RuntimeException("Cannot perform OP_TUCK on a stack with less than 2 elements")
                    op == OP_TUCK -> {
                        val x0 = stack[0]
                        val x1 = stack[1]
                        stack[0] = x1
                        stack[1] = x0
                        stack.add(0, x0)
                    }

                    op == OP_VERIFY && stack.isEmpty() -> throw RuntimeException("Cannot perform OP_VERIFY on an empty stack")
                    op == OP_VERIFY -> {
                        val x = stack.removeFirst()
                        require(castToBoolean(x)) { "OP_VERIFY failed" }
                    }

                    op == OP_WITHIN && stack.size < 3 -> throw RuntimeException("Cannot perform OP_WITHIN on a stack with less than 3 elements")
                    op == OP_WITHIN -> {
                        val max = decodeNumber(stack.removeFirst())
                        val min = decodeNumber(stack.removeFirst())
                        val n = decodeNumber(stack.removeFirst())
                        val result = if (n in min until max) 1 else 0
                        stack.add(0, encodeNumber(result))
                    }

                    else -> {
                        throw RuntimeException("unexpected operator $op")
                    }
                }

                require(stack.size + altstack.size <= MAX_STACK_SIZE) { "stack is too large: stack size = ${stack.size} alt stack size = ${altstack.size}" }
            }
            require(conditions.isEmpty()) { "IF/ENDIF imbalance" }
            return stack
        }

        public fun verifyWitnessProgram(witness: ScriptWitness, witnessVersion: Long, program: ByteArray, isP2sh: Boolean = false) {

            // check that the input stack contains a single "1" element, as it should be if script execution was correct
            fun checkFinalStack(stack: List<ByteVector>) {
                require(stack.size == 1)
                require(castToBoolean(stack.first()))
            }

            // reset taproot execution data
            this.context.executionData = ExecutionData.empty

            when {
                witnessVersion == 0L && program.size == WITNESS_V0_KEYHASH_SIZE -> {
                    // P2WPKH, program is simply the pubkey hash
                    require(witness.stack.count() == 2) { "Invalid witness program, should have 2 items" }
                    val finalStack = run(listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(program), OP_EQUALVERIFY, OP_CHECKSIG), witness.stack.reversed(), SigVersion.SIGVERSION_WITNESS_V0)
                    checkFinalStack(finalStack)
                }

                witnessVersion == 0L && program.size == WITNESS_V0_SCRIPTHASH_SIZE -> {
                    // P2WPSH, program is the hash of the script, and witness is the stack + the script
                    val check = Crypto.sha256(witness.stack.last())
                    require(check.contentEquals(program)) { "witness program mismatch" }
                    val finalStack = run(witness.stack.last(), witness.stack.dropLast(1).reversed(), SigVersion.SIGVERSION_WITNESS_V0)
                    checkFinalStack(finalStack)
                }

                witnessVersion == 0L -> throw IllegalArgumentException("Invalid witness program length: ${program.size}")
                witnessVersion == 1L && program.size == WITNESS_V1_TAPROOT_SIZE && !isP2sh -> {
                    // BIP341 Taproot: 32-byte non-P2SH witness v1 program (which encodes a P2C-tweaked pubkey)
                    if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_TAPROOT) == 0) return
                    require(witness.stack.isNotEmpty()) { "Witness program cannot be empty" }
                    val (stack, annex) = when {
                        witness.stack.size >= 2 && !witness.stack.last().isEmpty() && witness.stack.last()[0] == 0x50.toByte() -> Pair(witness.stack.dropLast(1), witness.stack.last())
                        else -> Pair(witness.stack, null)
                    }
                    this.context.executionData = this.context.executionData.copy(annex = annex)
                    // Key path spending (stack size is 1 after removing optional annex)
                    if (stack.size == 1) {
                        val sig = stack.first()
                        val pub = XonlyPublicKey(program.byteVector32())
                        val hashType = sigHashType(sig)
                        val hash = Transaction.hashForSigningSchnorr(
                            context.tx,
                            context.inputIndex,
                            context.prevouts,
                            hashType,
                            SigVersion.SIGVERSION_TAPROOT,
                            context.executionData.tapleafHash,
                            context.executionData.annex,
                            context.executionData.codeSeparatorPos
                        )
                        require(Secp256k1.verifySchnorr(sig.take(64).toByteArray(), hash.toByteArray(), pub.value.toByteArray())) { " invalid Schnorr signature " }
                        return
                    } else {
                        val outputKey = XonlyPublicKey(program.byteVector32())
                        val script = stack[stack.size - 2]
                        val control = stack[stack.size - 1]
                        require((control.size() - 33).mod(32) == 0) { "invalid control block size" }
                        require((control.size() - 33) / 32 in 0..128) { "invalid control block size" }
                        val leafVersion = control[0].toInt() and TAPROOT_LEAF_MASK
                        val internalKey = XonlyPublicKey(control.slice(1, 33).toByteArray().byteVector32())
                        val tapleafHash = ScriptTree.Leaf(script, leafVersion).hash()
                        this.context.executionData = this.context.executionData.copy(tapleafHash = tapleafHash)

                        // split input buffer into 32 bytes chunks (input buffer size MUST be a multiple of 32 !!)
                        tailrec fun split32(input: ByteVector, acc: List<ByteVector32> = listOf()): List<ByteVector32> = when {
                            input.size() == 0 -> acc
                            else -> split32(input.drop(32), acc + input.take(32).toByteArray().byteVector32())
                        }

                        val leaves = split32(control.drop(33))
                        val merkleRoot = leaves.fold(tapleafHash) { a, b ->
                            Crypto.taggedHash(if (LexicographicalOrdering.isLessThan(a, b)) a.toByteArray() + b.toByteArray() else b.toByteArray() + a.toByteArray(), "TapBranch")
                        }
                        val parity = (control[0].toInt() and 0x01) == 0x01
                        require(Pair(outputKey, parity) == internalKey.outputKey(Crypto.TaprootTweak.ScriptTweak(merkleRoot)))

                        if (leafVersion == TAPROOT_LEAF_TAPSCRIPT) {
                            this.context.executionData = this.context.executionData.copy(validationWeightLeft = ScriptWitness.write(witness).size + VALIDATION_WEIGHT_OFFSET)

                            tailrec fun hasOpSuccess(it: Iterator<ScriptElt>): Boolean = when {
                                !it.hasNext() -> false
                                isOpSuccess(it.next().code) -> true
                                else -> hasOpSuccess(it)
                            }
                            if (hasOpSuccess(scriptIterator(script.toByteArray()))) {
                                require(scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS == 0) { "OP_SUCCESSx reserved for soft-fork upgrades" }
                                return
                            }
                            val stack1 = stack.dropLast(2).reversed()
                            require(stack1.size <= MAX_STACK_SIZE) { "Stack size limit exceeded" }
                            val finalStack = run(script, stack1, SigVersion.SIGVERSION_TAPSCRIPT)
                            checkFinalStack(finalStack)
                        } else {
                            require(scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION == 0) { "Taproot version $leafVersion reserved for soft-fork upgrades" }
                        }
                    }
                }
                // Standard P2A script (see github.com/bitcoin/bitcoin/pull/30352).
                witnessVersion == 1L && program.contentEquals(byteArrayOf(0x4e, 0x73)) -> require(witness == witnessPay2anchor) { "P2A output must be spent with an empty witness" }
                (scriptFlag and ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) != 0 -> throw IllegalArgumentException("Witness version $witnessVersion reserved for soft-fork upgrades")
                // Higher version witness scripts return true for future softfork compatibility
                else -> {}
            }
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
            fun checkStack(stack: List<ByteVector>): Boolean = when {
                stack.isEmpty() -> false
                !castToBoolean(stack.first()) -> false
                (scriptFlag and ScriptFlags.SCRIPT_VERIFY_CLEANSTACK) != 0 -> {
                    if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_P2SH) == 0) throw RuntimeException("illegal script flag")
                    stack.size == 1
                }

                else -> true
            }


            if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_WITNESS) != 0) {
                // We can't check for correct unexpected witness data if P2SH was off, so require
                // that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
                // possible, which is not a softfork.
                require((scriptFlag and ScriptFlags.SCRIPT_VERIFY_P2SH) != 0)
            }
            val ssig = parse(scriptSig)
            if (((scriptFlag and ScriptFlags.SCRIPT_VERIFY_SIGPUSHONLY) != 0) && !isPushOnly(ssig)) throw RuntimeException("signature script is not PUSH-only")
            val stack = run(scriptSig, listOf(), signatureVersion = 0)

            val spub = parse(scriptPubKey)
            val stack0 = run(scriptPubKey, stack, signatureVersion = 0)
            require(stack0.isNotEmpty()) { "Script verification failed, stack should not be empty" }
            require(castToBoolean(stack0.first())) { "Script verification failed, stack starts with 'false'" }

            var hadWitness = false

            fun isWitnessProgram(script: List<ScriptElt>): Boolean =
                script.size == 2 && isSimpleValue(script[0]) && simpleValue(script[0]).toInt() in 0..16 && script[1] is OP_PUSHDATA

            val stack1 = if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_WITNESS) != 0 && isWitnessProgram(spub)) {
                val witnessVersion = simpleValue(spub[0])
                val program = spub[1] as OP_PUSHDATA
                when {
                    OP_PUSHDATA.isMinimal(program.data.toByteArray(), program.code) && program.data.size() in 2..40 -> {
                        hadWitness = true
                        require(ssig.isEmpty()) { "Malleated segwit script" }
                        verifyWitnessProgram(witness, witnessVersion.toLong(), program.data.toByteArray(), isP2sh = false)
                        stack0.take(1)
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
                require(stackp2sh.isNotEmpty()) { "Script verification failed, stack should not be empty" }
                require(castToBoolean(stackp2sh.first())) { "Script verification failed, stack starts with 'false'" }

                if ((scriptFlag and ScriptFlags.SCRIPT_VERIFY_WITNESS) != 0) {
                    val program = parse(stack.first())
                    when {
                        program.size == 2 && isSimpleValue(program[0]) && pushSize(program[1]) in 2..40 -> {
                            hadWitness = true
                            val witnessVersion = simpleValue(program[0])
                            verifyWitnessProgram(witness, witnessVersion.toLong(), (program[1] as OP_PUSHDATA).data.toByteArray(), isP2sh = true)
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
