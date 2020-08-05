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

import fr.acinq.bitcoin.Protocol.PROTOCOL_VERSION
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Input
import fr.acinq.bitcoin.io.Output
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

/**
 * an out point is a reference to a specific output in a specific transaction that we want to claim
 *
 * @param hash  reversed sha256(sha256(tx)) where tx is the transaction we want to refer to
 * @param index index of the output in tx that we want to refer to
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
public data class OutPoint(@JvmField val hash: ByteVector32, @JvmField val index: Long) : BtcSerializable<OutPoint> {
    public constructor(hash: ByteArray, index: Long) : this(hash.byteVector32(), index)

    public constructor(tx: Transaction, index: Long) : this(tx.hash, index)

    init {
        require(index >= -1)
    }

    /**
     *
     * @return the id of the transaction this output belongs to
     */
    @JvmField
    public val txid: ByteVector32 = hash.reversed()

    @JvmField
    public val isCoinbase: Boolean = isCoinbase(this)

    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    public companion object : BtcSerializer<OutPoint>() {
        override fun read(input: Input, protocolVersion: Long): OutPoint = OutPoint(hash(input), uint32(input).toLong())

        @JvmStatic
        override fun read(input: ByteArray): OutPoint {
            return super.read(input)
        }

        override fun write(message: OutPoint, out: Output, protocolVersion: Long) {
            out.write(message.hash.toByteArray())
            writeUInt32(message.index.toUInt(), out)
        }

        @JvmStatic
        override fun write(message: OutPoint): ByteArray {
            return super.write(message)
        }

        public fun isCoinbase(input: OutPoint): Boolean = input.index == 0xffffffffL && input.hash == ByteVector32.Zeroes

        public fun isNull(input: OutPoint): Boolean = isCoinbase(input)
    }

    override fun serializer(): BtcSerializer<OutPoint> = OutPoint
}

@Serializable
public data class ScriptWitness(@JvmField val stack: List<ByteVector>) : BtcSerializable<ScriptWitness> {
    public constructor() : this(listOf())

    public fun isNull(): Boolean = stack.isEmpty()

    public fun isNotNull(): Boolean = !isNull()

    public fun push(item: ByteVector): ScriptWitness = this.copy(stack = this.stack + item)

    public fun push(item: ByteArray): ScriptWitness = push(ByteVector(item))

    public fun push(script: List<ScriptElt>): ScriptWitness = push(Script.write(script))

    public fun last(): ByteVector = stack.last()

    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    public companion object : BtcSerializer<ScriptWitness>() {
        public val empty: ScriptWitness = ScriptWitness(listOf())

        override fun read(input: Input, protocolVersion: Long): ScriptWitness {
            return ScriptWitness(
                readCollection(
                    input,
                    { i, _ -> script(i).byteVector() },
                    null,
                    protocolVersion
                )
            )
        }

        override fun write(t: ScriptWitness, out: Output, protocolVersion: Long) {
            writeCollection(t.stack, out, { b, o, _ -> writeScript(b, o) }, protocolVersion)
        }
    }

    override fun serializer(): BtcSerializer<ScriptWitness> = ScriptWitness
}

/**
 * Transaction input
 *
 * @param outPoint        Previous output transaction reference
 * @param signatureScript Signature script which should match the public key script of the output that we want to spend
 * @param sequence        Transaction version as defined by the sender. Intended for "replacement" of transactions when
 *                        information is updated before inclusion into a block. Repurposed for OP_CSV (see BIPs 68 & 112)
 * @param witness         Transaction witness (i.e. what is in sig script for standard transactions).
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
public data class TxIn(
    @JvmField val outPoint: OutPoint,
    @JvmField val signatureScript: ByteVector,
    @JvmField val sequence: Long,
    @JvmField val witness: ScriptWitness = ScriptWitness.empty
) : BtcSerializable<TxIn> {

    public constructor(outPoint: OutPoint, signatureScript: ByteArray, sequence: Long) : this(
        outPoint,
        signatureScript.byteVector(),
        sequence
    )

    public constructor(outPoint: OutPoint, sequence: Long) : this(outPoint, ByteVector.empty, sequence)

    public constructor(outPoint: OutPoint, signatureScript: List<ScriptElt>, sequence: Long) : this(
        outPoint,
        Script.write(signatureScript),
        sequence
    )

    @JvmField
    public val isFinal: Boolean = sequence == SEQUENCE_FINAL

    @JvmField
    public val hasWitness: Boolean = witness.isNotNull()

    public fun updateSignatureScript(signatureScript: ByteVector): TxIn = this.copy(signatureScript = signatureScript)

    public fun updateSignatureScript(signatureScript: ByteArray): TxIn = this.copy(signatureScript = ByteVector(signatureScript))

    public fun updateWitness(witness: ScriptWitness): TxIn = this.copy(witness = witness)

    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    public companion object : BtcSerializer<TxIn>() {
        /* Setting nSequence to this value for every input in a transaction disables nLockTime. */
        public const val SEQUENCE_FINAL: Long = 0xffffffffL

        /* Below flags apply in the context of BIP 68*/
        /* If this flag set, CTxIn::nSequence is NOT interpreted as a relative lock-time. */
        public const val SEQUENCE_LOCKTIME_DISABLE_FLAG: Long = (1L shl 31)

        /* If CTxIn::nSequence encodes a relative lock-time and this flag
         * is set, the relative lock-time has units of 512 seconds,
         * otherwise it specifies blocks with a granularity of 1. */
        public const val SEQUENCE_LOCKTIME_TYPE_FLAG: Long = (1L shl 22)

        /* If CTxIn::nSequence encodes a relative lock-time, this mask is
         * applied to extract that lock-time from the sequence field. */
        public const val SEQUENCE_LOCKTIME_MASK: Long = 0x0000ffffL

        /* In order to use the same number of bits to encode roughly the
         * same wall-clock duration, and because blocks are naturally
         * limited to occur every 600s on average, the minimum granularity
         * for time-based relative lock-time is fixed at 512 seconds.
         * Converting from CTxIn::nSequence to seconds is performed by
         * multiplying by 512 = 2^9, or equivalently shifting up by
         * 9 bits. */
        public const val SEQUENCE_LOCKTIME_GRANULARITY: Long = 9L

        override fun read(input: Input, protocolVersion: Long): TxIn = TxIn(
            outPoint = OutPoint.read(input),
            signatureScript = script(input),
            sequence = uint32(input).toLong()
        )

        override fun write(message: TxIn, out: Output, protocolVersion: Long) {
            OutPoint.write(message.outPoint, out)
            writeScript(message.signatureScript, out)
            writeUInt32(message.sequence.toUInt(), out)
        }

        override fun validate(input: TxIn) {
            require(input.signatureScript.size() <= Script.MaxScriptElementSize) { "signature script is ${input.signatureScript.size()} bytes, limit is $Script.MaxScriptElementSize bytes" }
        }

        public fun coinbase(script: ByteArray): TxIn {
            require(script.size in 2..100) { "coinbase script length must be between 2 and 100" }
            return TxIn(OutPoint(ByteArray(32), 0xffffffffL), script, sequence = 0xffffffffL)
        }

        public fun coinbase(script: List<ScriptElt>): TxIn = coinbase(Script.write(script))
    }

    override fun serializer(): BtcSerializer<TxIn> = TxIn
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
public data class TxOut(@JvmField val amount: Satoshi, @JvmField val publicKeyScript: ByteVector) : BtcSerializable<TxOut> {

    public constructor(amount: Satoshi, publicKeyScript: ByteArray) : this(amount, publicKeyScript.byteVector())

    public constructor(amount: Satoshi, publicKeyScript: List<ScriptElt>) : this(
        amount,
        Script.write(publicKeyScript).byteVector()
    )

    public fun updateAmount(newAmount: Satoshi): TxOut = this.copy(amount = newAmount)

    public fun updatePublicKeyScript(input: ByteVector): TxOut = this.copy(publicKeyScript = input)

    public fun updatePublicKeyScript(input: ByteArray): TxOut = updatePublicKeyScript(input.byteVector())

    public fun updatePublicKeyScript(input: List<ScriptElt>): TxOut = updatePublicKeyScript(Script.write(input))

    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    public companion object : BtcSerializer<TxOut>() {
        override fun write(t: TxOut, out: Output, protocolVersion: Long) {
            writeUInt64(t.amount.toLong().toULong(), out)
            writeScript(t.publicKeyScript, out)
        }

        @JvmStatic
        override fun write(message: TxOut): ByteArray {
            return super.write(message)
        }

        override fun read(input: Input, protocolVersion: Long): TxOut =
            TxOut(uint64(input).toLong().toSatoshi(), script(input))

        @JvmStatic
        override fun read(input: ByteArray): TxOut {
            return super.read(input)
        }

        override fun validate(t: TxOut) {
            require(t.amount.sat >= 0) { "invalid txout amount: $t.amount" }
            // TODO require(t.amount.amount <= Bitcoin.MaxMoney) { "invalid txout amount: $t.amount" }
            require(t.publicKeyScript.size() < Script.MaxScriptElementSize) { "public key script is ${t.publicKeyScript.size()} bytes, limit is $Script.MaxScriptElementSize bytes" }
        }
    }

    override fun serializer(): BtcSerializer<TxOut> = TxOut
}

@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
public data class Transaction(
    @JvmField val version: Long,
    @JvmField val txIn: List<TxIn>,
    @JvmField val txOut: List<TxOut>,
    @JvmField val lockTime: Long
) :
    BtcSerializable<Transaction> {

    @JvmField
    public val hasWitness: Boolean = txIn.any { it.hasWitness }

    @JvmField
    public val hash: ByteVector32 = ByteVector32(
        Crypto.hash256(
            Transaction.write(
                this,
                SERIALIZE_TRANSACTION_NO_WITNESS
            )
        )
    )

    @JvmField
    public val txid: ByteVector32 = hash.reversed()

    /**
     *
     * @param i         index of the tx input to update
     * @param sigScript new signature script
     * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
     */
    public fun updateSigScript(i: Int, sigScript: ByteArray): Transaction {
        val updatedElement = txIn[i].copy(signatureScript = sigScript.byteVector())
        val updated = txIn.toMutableList().apply {
            this[i] = updatedElement
        }
        return this.copy(txIn = updated.toList())
    }

    /**
     *
     * @param i         index of the tx input to update
     * @param sigScript new signature script
     * @return a new transaction that is of copy of this one but where the signature script of the ith input has been replace by sigscript
     */
    public fun updateSigScript(i: Int, sigScript: List<ScriptElt>): Transaction = updateSigScript(i, Script.write(sigScript))

    public fun updateWitness(i: Int, witness: ScriptWitness): Transaction {
        val updatedElement = txIn[i].copy(witness = witness)
        val updated = txIn.toMutableList().apply {
            this[i] = updatedElement
        }
        return this.copy(txIn = updated.toList())
    }

    public fun updateWitnesses(witnesses: List<ScriptWitness>): Transaction {
        require(witnesses.count() == txIn.count())
        var tx = this
        for (i in 0..txIn.lastIndex) {
            tx = tx.updateWitness(i, witnesses[i])
        }
        return tx
    }

    public fun updateInputs(inputs: List<TxIn>): Transaction = this.copy(txIn = inputs)

    public fun addInput(input: TxIn): Transaction = this.copy(txIn = this.txIn + input)

    public fun updateOutputs(outputs: List<TxOut>): Transaction = this.copy(txOut = outputs)

    public fun addOutput(output: TxOut): Transaction = this.copy(txOut = this.txOut + output)

    public fun weight(): Int = weight(this)

    override fun toString(): String {
        return Hex.encode(write(this))
    }

    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    public companion object : BtcSerializer<Transaction>() {
        public const val SERIALIZE_TRANSACTION_NO_WITNESS: Long = 0x40000000L

        // if lockTime >= LOCKTIME_THRESHOLD it is a unix timestamp otherwise it is a block height
        public const val LOCKTIME_THRESHOLD: Long = 500000000L

        /**
         *
         * @param version protocol version (and NOT transaction version !)
         * @return true if protocol version specifies that witness data is to be serialized
         */
        @JvmStatic
        public fun serializeTxWitness(version: Long): Boolean = (version and SERIALIZE_TRANSACTION_NO_WITNESS) == 0L

        @JvmStatic
        override fun write(tx: Transaction, out: Output, protocolVersion: Long) {
            if (serializeTxWitness(protocolVersion) && tx.hasWitness) {
                writeUInt32(tx.version.toUInt(), out)
                writeUInt8(0x00u, out)
                writeUInt8(0x01u, out)
                writeCollection(tx.txIn, out, TxIn, protocolVersion)
                writeCollection(tx.txOut, out, TxOut, protocolVersion)
                tx.txIn.forEach { it -> ScriptWitness.write(it.witness, out, protocolVersion) }
                writeUInt32(tx.lockTime.toUInt(), out)
            } else {
                writeUInt32(tx.version.toUInt(), out)
                writeCollection(tx.txIn, out, TxIn, protocolVersion)
                writeCollection(tx.txOut, out, TxOut, protocolVersion)
                writeUInt32(tx.lockTime.toUInt(), out)
            }
        }

        @JvmStatic
        override fun write(message: Transaction): ByteArray = super.write(message)

        @JvmStatic
        override fun read(input: Input, protocolVersion: Long): Transaction {
            val tx = Transaction(uint32(input).toLong(), readCollection(input, TxIn, protocolVersion), listOf(), 0)
            val (flags, tx1) = if (tx.txIn.count() == 0 && serializeTxWitness(protocolVersion)) {
                // we just read the 0x00 marker
                val flags = uint8(input).toInt()
                val txIn = readCollection(input, TxIn, protocolVersion)
                if (flags == 0 && txIn.count() != 0) throw RuntimeException("Extended transaction format unnecessarily used")
                val txOut = readCollection(input, TxOut, protocolVersion)
                Pair(flags, tx.copy(txIn = txIn, txOut = txOut))
            } else Pair(0, tx.copy(txOut = readCollection(input, TxOut, protocolVersion)))

            val tx2 = when (flags) {
                0 -> tx1.copy(lockTime = uint32(input).toLong())
                1 -> {
                    val witnesses = mutableListOf<ScriptWitness>()
                    for (i in 0..tx1.txIn.lastIndex) witnesses += ScriptWitness.read(input, protocolVersion)
                    tx1.updateWitnesses(witnesses.toList()).copy(lockTime = uint32(input).toLong())
                }
                else -> throw RuntimeException("Unknown transaction optional data $flags")
            }

            return tx2
        }

        @JvmStatic
        override fun read(input: String): Transaction {
            return super.read(input)
        }

        @JvmStatic
        override fun read(input: ByteArray): Transaction {
            return super.read(input)
        }

        @JvmStatic
        override fun validate(input: Transaction) {
            require(input.txIn.count() > 0) { "input list cannot be empty" }
            require(input.txOut.count() > 0) { "output list cannot be empty" }
            // require(Transaction.write(input).size <= Bitcoin.MaxBlockSize)
            // require(input.txOut.map { it.amount }.sum().toLong() <= Bitcoin.MaxMoney) { "sum of outputs amount is invalid" }
            input.txIn.forEach { TxIn.validate(it) }
            input.txOut.forEach { TxOut.validate(it) }
            val outPoints = input.txIn.map { it.outPoint }
            require(outPoints.count() == outPoints.toSet().size) { "duplicate inputs" }
            if (isCoinbase(input)) {
                require(input.txIn.first().signatureScript.size() >= 2) { "coinbase script size" }
                require(input.txIn.first().signatureScript.size() <= 100) { "coinbase script size" }
            } else {
                require(input.txIn.all { !OutPoint.isCoinbase(it.outPoint) }) { "prevout is null" }
            }
        }

        @JvmStatic
        public fun baseSize(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int =
            write(tx, protocolVersion or SERIALIZE_TRANSACTION_NO_WITNESS).size

        @JvmStatic
        public fun totalSize(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int = write(tx, protocolVersion).size

        @JvmStatic
        public fun weight(tx: Transaction, protocolVersion: Long = PROTOCOL_VERSION): Int =
            totalSize(tx, protocolVersion) + 3 * baseSize(tx, protocolVersion)

        @JvmStatic
        public fun weight(tx: Transaction): Int = weight(tx, PROTOCOL_VERSION)


        @JvmStatic
        public fun isCoinbase(input: Transaction): Boolean = input.txIn.count() == 1 && OutPoint.isCoinbase(input.txIn.first().outPoint)

        /**
         * prepare a transaction for signing a specific input
         *
         * @param tx                   input transaction
         * @param inputIndex           index of the tx input that is being processed
         * @param previousOutputScript public key script of the output claimed by this tx input
         * @param sighashType          signature hash type
         * @return a new transaction with proper inputs and outputs according to SIGHASH_TYPE rules
         */
        @JvmStatic
        public fun prepareForSigning(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: ByteArray,
            sighashType: Int
        ): Transaction {
            val filteredScript =
                Script.write(Script.parse(previousOutputScript).filterNot { it -> it == OP_CODESEPARATOR })

            fun removeSignatureScript(txin: TxIn): TxIn = txin.copy(signatureScript = ByteVector.empty)

            fun removeAllSignatureScripts(tx: Transaction): Transaction =
                tx.copy(txIn = tx.txIn.map { removeSignatureScript(it) })

            fun updateSignatureScript(tx: Transaction, index: Int, script: ByteArray): Transaction =
                tx.updateSigScript(index, script)

            fun resetSequence(txins: List<TxIn>, inputIndex: Int): List<TxIn> {
                val result = txins.toMutableList()
                for (i in 0..result.lastIndex) {
                    if (i != inputIndex) result[i] = result[i].copy(sequence = 0L)
                }
                return result.toList()
            }

            val tx1 = removeAllSignatureScripts(tx)
            val tx2 = updateSignatureScript(tx1, inputIndex, filteredScript)
            val tx3 = when {
                SigHash.isHashNone(sighashType) -> {
                    // hash none: remove all outputs
                    val inputs = resetSequence(tx2.txIn, inputIndex)
                    tx2.copy(txIn = inputs, txOut = listOf())
                }
                SigHash.isHashSingle(sighashType) -> {
                    // hash single: remove all outputs but the one that we are trying to claim
                    val inputs = resetSequence(tx2.txIn, inputIndex)
                    val outputs = mutableListOf<TxOut>()
                    for (i in 0..inputIndex) {
                        outputs += if (i == inputIndex) tx2.txOut[inputIndex] else TxOut((-1L).toSatoshi(), ByteArray(0))
                    }
                    tx2.copy(txIn = inputs, txOut = outputs.toList())
                }
                else -> tx2
            }

            val tx4 = if (SigHash.isAnyoneCanPay(sighashType)) tx3.copy(txIn = listOf(tx3.txIn[inputIndex])) else tx3
            return tx4
        }

        /**
         * hash a tx for signing (pre-segwit)
         *
         * @param tx                   input transaction
         * @param inputIndex           index of the tx input that is being processed
         * @param previousOutputScript public key script of the output claimed by this tx input
         * @param sighashType          signature hash type
         * @return a hash which can be used to sign the referenced tx input
         */
        @JvmStatic
        public fun hashForSigning(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: ByteArray,
            sighashType: Int
        ): ByteArray {
            return if (SigHash.isHashSingle(sighashType) && inputIndex >= tx.txOut.count()) {
                ByteVector32.One.toByteArray()
            } else {
                val txCopy = prepareForSigning(tx, inputIndex, previousOutputScript, sighashType)
                Crypto.hash256(
                    Transaction.write(txCopy, SERIALIZE_TRANSACTION_NO_WITNESS) + writeUInt32(
                        sighashType.toUInt()
                    )
                )
            }
        }

        /**
         * hash a tx for signing
         *
         * @param tx                   input transaction
         * @param inputIndex           index of the tx input that is being processed
         * @param previousOutputScript public key script of the output claimed by this tx input
         * @param sighashType          signature hash type
         * @param amount               amount of the output claimed by this input
         * @return a hash which can be used to sign the referenced tx input
         */
        @JvmStatic
        public fun hashForSigning(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: ByteArray,
            sighashType: Int,
            amount: Satoshi,
            signatureVersion: Int
        ): ByteArray {
            when (signatureVersion) {
                SigVersion.SIGVERSION_WITNESS_V0 -> {
                    val hashPrevOut = if (!SigHash.isAnyoneCanPay(sighashType)) {
                        val arrays = tx.txIn.map { it.outPoint }.map { OutPoint.write(it, PROTOCOL_VERSION) }
                        val concatenated = arrays.fold(ByteArray(0)) { acc, b -> acc + b }
                        Crypto.hash256(concatenated)
                    } else ByteArray(32)

                    val hashSequence =
                        if (!SigHash.isAnyoneCanPay(sighashType) && !SigHash.isHashSingle(sighashType) && !SigHash.isHashNone(
                                sighashType
                            )
                        ) {
                            val arrays = tx.txIn.map { it.sequence }.map { writeUInt32(it.toUInt()) }
                            val concatenated = arrays.fold(ByteArray(0)) { acc, b -> acc + b }
                            Crypto.hash256(concatenated)
                        } else ByteArray(32)

                    val hashOutputs = if (!SigHash.isHashSingle(sighashType) && !SigHash.isHashNone(sighashType)) {
                        val arrays = tx.txOut.map { TxOut.write(it, PROTOCOL_VERSION) }
                        val concatenated = arrays.fold(ByteArray(0)) { acc, b -> acc + b }
                        Crypto.hash256(concatenated)
                    } else if (SigHash.isHashSingle(sighashType) && inputIndex < tx.txOut.count()) {
                        Crypto.hash256(TxOut.write(tx.txOut[inputIndex], PROTOCOL_VERSION))
                    } else ByteArray(32)

                    val out = ByteArrayOutput()
                    writeUInt32(tx.version.toUInt(), out)
                    out.write(hashPrevOut)
                    out.write(hashSequence)
                    out.write(OutPoint.write(tx.txIn.elementAt(inputIndex).outPoint, PROTOCOL_VERSION))
                    writeScript(previousOutputScript, out)
                    writeUInt64(amount.toULong(), out)
                    writeUInt32(tx.txIn[inputIndex].sequence.toUInt(), out)
                    out.write(hashOutputs)
                    writeUInt32(tx.lockTime.toUInt(), out)
                    writeUInt32(sighashType.toUInt(), out)
                    val preimage = out.toByteArray()
                    return Crypto.hash256(preimage)
                }
                else -> return hashForSigning(tx, inputIndex, previousOutputScript, sighashType)
            }
        }

        /**
         * hash a tx for signing
         *
         * @param tx                   input transaction
         * @param inputIndex           index of the tx input that is being processed
         * @param previousOutputScript public key script of the output claimed by this tx input
         * @param sighashType          signature hash type
         * @param amount               amount of the output claimed by this input
         * @return a hash which can be used to sign the referenced tx input
         */
        @JvmStatic
        public fun hashForSigning(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: List<ScriptElt>,
            sighashType: Int,
            amount: Satoshi,
            signatureVersion: Int
        ): ByteArray =
            hashForSigning(tx, inputIndex, Script.write(previousOutputScript), sighashType, amount, signatureVersion)

        /**
         * sign a tx input
         *
         * @param tx                   input transaction
         * @param inputIndex           index of the tx input that is being processed
         * @param previousOutputScript public key script of the output claimed by this tx input
         * @param sighashType          signature hash type, which will be appended to the signature
         * @param amount               amount of the output claimed by this tx input
         * @param signatureVersion     signature version (1: segwit, 0: pre-segwit)
         * @param privateKey           private key
         * @return the encoded signature of this tx for this specific tx input
         */
        @JvmStatic
        public fun signInput(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: ByteArray,
            sighashType: Int,
            amount: Satoshi,
            signatureVersion: Int,
            privateKey: PrivateKey
        ): ByteArray {
            val hash = hashForSigning(tx, inputIndex, previousOutputScript, sighashType, amount, signatureVersion)
            val sig = Crypto.sign(hash, privateKey)
            return Crypto.compact2der(sig).toByteArray() + (sighashType.toByte())
        }

        @JvmStatic
        public fun signInput(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: ByteVector,
            sighashType: Int,
            amount: Satoshi,
            signatureVersion: Int,
            privateKey: PrivateKey
        ): ByteArray = signInput(
            tx,
            inputIndex,
            previousOutputScript.toByteArray(),
            sighashType,
            amount,
            signatureVersion,
            privateKey
        )

        /**
         * sign a tx input
         *
         * @param tx                   input transaction
         * @param inputIndex           index of the tx input that is being processed
         * @param previousOutputScript public key script of the output claimed by this tx input
         * @param sighashType          signature hash type, which will be appended to the signature
         * @param amount               amount of the output claimed by this tx input
         * @param signatureVersion     signature version (1: segwit, 0: pre-segwit)
         * @param privateKey           private key
         * @return the encoded signature of this tx for this specific tx input
         */
        @JvmStatic
        public fun signInput(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: List<ScriptElt>,
            sighashType: Int,
            amount: Satoshi,
            signatureVersion: Int,
            privateKey: PrivateKey
        ): ByteArray =
            signInput(
                tx,
                inputIndex,
                Script.write(previousOutputScript),
                sighashType,
                amount,
                signatureVersion,
                privateKey
            )

        /**
         *
         * @param tx                   input transaction
         * @param inputIndex           index of the tx input that is being processed
         * @param previousOutputScript public key script of the output claimed by this tx input
         * @param sighashType          signature hash type, which will be appended to the signature
         * @param privateKey           private key
         * @return the encoded signature of this tx for this specific tx input
         */
        @JvmStatic
        public fun signInput(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: ByteArray,
            sighashType: Int,
            privateKey: PrivateKey
        ): ByteArray =
            signInput(
                tx,
                inputIndex,
                previousOutputScript,
                sighashType,
                Satoshi(0L),
                SigVersion.SIGVERSION_BASE,
                privateKey
            )

        @JvmStatic
        public fun signInput(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: ByteVector,
            sighashType: Int,
            privateKey: PrivateKey
        ): ByteArray =
            signInput(tx, inputIndex, previousOutputScript.toByteArray(), sighashType, privateKey)

        @JvmStatic
        public fun signInput(
            tx: Transaction,
            inputIndex: Int,
            previousOutputScript: List<ScriptElt>,
            sighashType: Int,
            privateKey: PrivateKey
        ): ByteArray =
            signInput(tx, inputIndex, Script.write(previousOutputScript), sighashType, privateKey)

        @JvmStatic
        public fun correctlySpends(
            tx: Transaction,
            previousOutputs: Map<OutPoint, TxOut>,
            scriptFlags: Int,
            callback: RunnerCallback? = null
        ) {
            for (i in 0 until tx.txIn.count()) {
                if (OutPoint.isCoinbase(tx.txIn.elementAt(i).outPoint)) continue
                val prevOutput = previousOutputs.getValue(tx.txIn[i].outPoint)
                val prevOutputScript = prevOutput.publicKeyScript
                val amount = prevOutput.amount
                val ctx = Script.Context(tx, i, amount)
                val runner = Script.Runner(ctx, scriptFlags, callback)
                if (!runner.verifyScripts(
                        tx.txIn[i].signatureScript,
                        prevOutputScript,
                        tx.txIn[i].witness
                    )
                ) throw RuntimeException("tx ${tx.txid} does not spend its input # $i")
            }
        }

        @JvmStatic
        public fun correctlySpends(tx: Transaction, previousOutputs: Map<OutPoint, TxOut>, scriptFlags: Int): Unit =
            correctlySpends(tx, previousOutputs, scriptFlags, null)

        @JvmStatic
        public fun correctlySpends(
            tx: Transaction,
            inputs: List<Transaction>,
            scriptFlags: Int,
            callback: RunnerCallback?
        ) {
            val map = mutableMapOf<OutPoint, TxOut>()
            for (outPoint in tx.txIn.map { it.outPoint }) {
                val prevTx = inputs.find { it.txid == outPoint.txid }
                val prevOut = prevTx?.txOut!![outPoint.index.toInt()]
                map.put(outPoint, prevOut)
            }
            correctlySpends(tx, map.toMap(), scriptFlags, callback)
        }

        @JvmStatic
        public fun correctlySpends(
            tx: Transaction,
            inputs: List<Transaction>,
            scriptFlags: Int
        ): Unit = correctlySpends(tx, inputs, scriptFlags, null)

        @JvmStatic
        public fun correctlySpends(
            tx: Transaction,
            parent: Transaction,
            scriptFlags: Int,
            callback: RunnerCallback?
        ): Unit = correctlySpends(tx, listOf(parent), scriptFlags, callback)

        @JvmStatic
        public fun correctlySpends(
            tx: Transaction,
            parent: Transaction,
            scriptFlags: Int
        ): Unit = correctlySpends(tx, listOf(parent), scriptFlags, null)
    }

    override fun serializer(): BtcSerializer<Transaction> = Transaction
}
