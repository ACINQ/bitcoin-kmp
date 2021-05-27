/*
 * Copyright 2021 ACINQ SAS
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

import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.bitcoin.io.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.getOrElse

/**
 * A partially signed bitcoin transaction: see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki.
 *
 * @param global global psbt data containing the transaction to be signed.
 * @param inputs signing data for each input of the transaction to be signed (order matches the unsigned tx).
 * @param outputs signing data for each output of the transaction to be signed (order matches the unsigned tx).
 */
@OptIn(ExperimentalUnsignedTypes::class)
public data class Psbt(val global: Global, val inputs: List<PartiallySignedInput>, val outputs: List<PartiallySignedOutput>) {

    init {
        require(global.tx.txIn.size == inputs.size) { "there must be one partially signed input per input of the unsigned tx" }
        require(global.tx.txOut.size == outputs.size) { "there must be one partially signed output per output of the unsigned tx" }
    }

    /**
     * Implements the PSBT creator role; initializes a PSBT for the given unsigned transaction.
     *
     * @param tx unsigned transaction skeleton.
     * @return the psbt with empty inputs and outputs.
     */
    public constructor(tx: Transaction) : this(
        Global(Version, tx.copy(txIn = tx.txIn.map { it.copy(signatureScript = ByteVector.empty, witness = ScriptWitness.empty) }), listOf(), listOf()),
        tx.txIn.map { PartiallySignedInput.empty },
        tx.txOut.map { PartiallySignedOutput.empty }
    )

    /**
     * Implements the PSBT updater role; adds information about a given UTXO.
     * Note that we always fill the nonWitnessUtxo (see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#cite_note-7).
     *
     * @param inputTx transaction containing the UTXO.
     * @param outputIndex index of the UTXO in the inputTx.
     * @param redeemScript redeem script if known and applicable.
     * @param witnessScript witness script if known and applicable.
     * @param sighashType sighash type if one should be specified.
     * @param derivationPaths derivation paths for keys used by this UTXO.
     * @return psbt with the matching input updated.
     */
    public fun update(
        inputTx: Transaction,
        outputIndex: Int,
        redeemScript: List<ScriptElt>? = null,
        witnessScript: List<ScriptElt>? = null,
        sighashType: Int? = null,
        derivationPaths: Map<PublicKey, KeyPathWithMaster> = mapOf()
    ): Either<UpdateFailure, Psbt> {
        if (outputIndex >= inputTx.txOut.size) return Either.Left(UpdateFailure.InvalidInput("output index must exist in the input tx"))
        val outpoint = OutPoint(inputTx, outputIndex.toLong())
        val inputIndex = global.tx.txIn.indexOfFirst { it.outPoint == outpoint }
        if (inputIndex < 0) return Either.Left(UpdateFailure.InvalidInput("psbt transaction does not spend the provided outpoint"))
        val input = inputs[inputIndex]
        val updated = when {
            witnessScript != null -> input.copy(
                witnessUtxo = inputTx.txOut[outputIndex],
                witnessScript = witnessScript,
                nonWitnessUtxo = inputTx,
                redeemScript = redeemScript ?: input.redeemScript,
                sighashType = sighashType ?: input.sighashType,
                derivationPaths = input.derivationPaths + derivationPaths
            )
            else -> input.copy(
                nonWitnessUtxo = inputTx,
                redeemScript = redeemScript ?: input.redeemScript,
                sighashType = sighashType ?: input.sighashType,
                derivationPaths = input.derivationPaths + derivationPaths
            )
        }
        return Either.Right(this.copy(inputs = inputs.updated(inputIndex, updated)))
    }

    /**
     * Implements the PSBT signer role: sign a given input.
     * The caller needs to carefully verify that it wants to spend that input, and that the unsigned transaction matches
     * what it expects.
     *
     * @param priv private key used to sign the input.
     * @param inputIndex index of the input that should be signed.
     * @return the psbt with a partial signature added (other inputs will not be modified).
     */
    public fun sign(priv: PrivateKey, inputIndex: Int): Either<UpdateFailure, Psbt> {
        if (inputIndex >= inputs.size) return Either.Left(UpdateFailure.InvalidInput("input index must exist in the input tx"))
        val input = inputs[inputIndex]
        val txIn = global.tx.txIn[inputIndex]
        return when {
            input.nonWitnessUtxo != null && input.nonWitnessUtxo.txid != txIn.outPoint.txid -> Either.Left(UpdateFailure.InvalidNonWitnessUtxo("non-witness utxo does not match unsigned tx input"))
            input.nonWitnessUtxo != null && input.nonWitnessUtxo.txOut.size <= txIn.outPoint.index -> Either.Left(UpdateFailure.InvalidNonWitnessUtxo("non-witness utxo index out of bounds"))
            input.witnessUtxo != null && !Script.isNativeWitnessScript(input.witnessUtxo.publicKeyScript) && !Script.isPayToScript(input.witnessUtxo.publicKeyScript.bytes) -> Either.Left(UpdateFailure.InvalidWitnessUtxo("witness utxo must use native witness program or P2SH witness program"))
            input.witnessUtxo != null -> {
                val utxo = input.witnessUtxo
                val redeemScript = when {
                    input.redeemScript != null -> {
                        // If a redeem script is provided in the partially signed input, the utxo must be a p2sh for that script.
                        val p2sh = Script.write(Script.pay2sh(input.redeemScript))
                        if (!utxo.publicKeyScript.contentEquals(p2sh)) {
                            return Either.Left(UpdateFailure.InvalidWitnessUtxo("redeem script does not match witness utxo scriptPubKey"))
                        }
                        input.redeemScript
                    }
                    else -> runCatching { Script.parse(utxo.publicKeyScript) }.getOrElse { return Either.Left(UpdateFailure.InvalidWitnessUtxo("failed to parse redeem script")) }
                }
                val sig = when {
                    input.witnessScript != null && !Script.isPay2wpkh(redeemScript) && redeemScript != Script.pay2wsh(input.witnessScript) -> return Either.Left(UpdateFailure.InvalidWitnessUtxo("witness script does not match redeemScript or scriptPubKey"))
                    input.witnessScript != null -> Transaction.signInput(global.tx, inputIndex, input.witnessScript, input.sighashType ?: SigHash.SIGHASH_ALL, utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, priv)
                    else -> Transaction.signInput(global.tx, inputIndex, redeemScript, input.sighashType ?: SigHash.SIGHASH_ALL, utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, priv)
                }
                Either.Right(this.copy(inputs = this.inputs.updated(inputIndex, input.copy(partialSigs = input.partialSigs + (priv.publicKey() to ByteVector(sig))))))
            }
            input.nonWitnessUtxo != null -> {
                val utxo = input.nonWitnessUtxo
                val redeemScript = when {
                    input.redeemScript != null -> {
                        // If a redeem script is provided in the partially signed input, the utxo must be a p2sh for that script.
                        val p2sh = Script.write(Script.pay2sh(input.redeemScript))
                        if (!utxo.txOut[txIn.outPoint.index.toInt()].publicKeyScript.contentEquals(p2sh)) {
                            return Either.Left(UpdateFailure.InvalidNonWitnessUtxo("redeem script does not match non-witness utxo scriptPubKey"))
                        }
                        input.redeemScript
                    }
                    else -> runCatching { Script.parse(utxo.txOut[txIn.outPoint.index.toInt()].publicKeyScript) }.getOrElse { return Either.Left(UpdateFailure.InvalidNonWitnessUtxo("failed to parse redeem script")) }
                }
                val amount = utxo.txOut[txIn.outPoint.index.toInt()].amount
                val sig = Transaction.signInput(global.tx, inputIndex, redeemScript, input.sighashType ?: SigHash.SIGHASH_ALL, amount, SigVersion.SIGVERSION_BASE, priv)
                Either.Right(this.copy(inputs = this.inputs.updated(inputIndex, input.copy(partialSigs = input.partialSigs + (priv.publicKey() to ByteVector(sig))))))
            }
            else -> Either.Right(this) // nothing to sign
        }
    }

    /**
     * Implements the PSBT finalizer role: finalizes a given non-witness input.
     * This will clear all fields from the input except the utxo, scriptSig and unknown entries.
     *
     * @param inputIndex index of the input that should be finalized.
     * @param scriptSig signature script.
     * @return a psbt with the given input finalized.
     */
    public fun finalize(inputIndex: Int, scriptSig: List<ScriptElt>): Either<UpdateFailure, Psbt> {
        return when {
            inputIndex >= inputs.size -> Either.Left(UpdateFailure.InvalidInput("input index must exist in the input tx"))
            inputs[inputIndex].nonWitnessUtxo == null -> Either.Left(UpdateFailure.CannotFinalizeInput(inputIndex, "non-witness utxo is missing"))
            else -> {
                val finalizedInput = inputs[inputIndex].copy(
                    sighashType = null,
                    partialSigs = mapOf(),
                    derivationPaths = mapOf(),
                    redeemScript = null,
                    witnessScript = null,
                    ripemd160 = setOf(),
                    sha256 = setOf(),
                    hash160 = setOf(),
                    hash256 = setOf(),
                    scriptSig = scriptSig
                )
                Either.Right(this.copy(inputs = this.inputs.updated(inputIndex, finalizedInput)))
            }
        }
    }

    /**
     * Implements the PSBT finalizer role: finalizes a given witness input.
     * This will clear all fields from the input except the utxo, scriptSig, scriptWitness and unknown entries.
     *
     * @param inputIndex index of the input that should be finalized.
     * @param scriptWitness witness script.
     * @return a psbt with the given input finalized.
     */
    public fun finalize(inputIndex: Int, scriptWitness: ScriptWitness): Either<UpdateFailure, Psbt> {
        return when {
            inputIndex >= inputs.size -> Either.Left(UpdateFailure.InvalidInput("input index must exist in the input tx"))
            inputs[inputIndex].witnessUtxo == null -> Either.Left(UpdateFailure.CannotFinalizeInput(inputIndex, "witness utxo is missing"))
            else -> {
                val input = inputs[inputIndex]
                val scriptSig = input.redeemScript?.let { listOf(OP_PUSHDATA(Script.write(it))) }
                val finalizedInput = input.copy(
                    sighashType = null,
                    partialSigs = mapOf(),
                    derivationPaths = mapOf(),
                    redeemScript = null,
                    witnessScript = null,
                    ripemd160 = setOf(),
                    sha256 = setOf(),
                    hash160 = setOf(),
                    hash256 = setOf(),
                    scriptSig = scriptSig,
                    scriptWitness = scriptWitness
                )
                Either.Right(this.copy(inputs = this.inputs.updated(inputIndex, finalizedInput)))
            }
        }
    }

    /**
     * Implements the PSBT extractor role: extracts a valid transaction from the psbt data.
     *
     * @return a fully signed, ready-to-broadcast transaction.
     */
    public fun extract(): Either<UpdateFailure, Transaction> {
        val (finalTxsIn, utxos) = global.tx.txIn.zip(inputs).map { (txIn, input) ->
            if (!isFinal(input)) {
                return Either.Left(UpdateFailure.CannotExtractTx("some inputs are not finalized"))
            }
            val finalTxIn = txIn.copy(
                witness = input.scriptWitness ?: ScriptWitness.empty,
                signatureScript = input.scriptSig?.let { ByteVector(Script.write(it)) } ?: ByteVector.empty
            )
            val utxo = when {
                input.nonWitnessUtxo != null && input.nonWitnessUtxo.txid != txIn.outPoint.txid -> return Either.Left(UpdateFailure.CannotExtractTx("non-witness utxo does not match unsigned tx input"))
                input.nonWitnessUtxo != null && input.nonWitnessUtxo.txOut.size <= txIn.outPoint.index -> return Either.Left(UpdateFailure.CannotExtractTx("non-witness utxo index out of bounds"))
                input.nonWitnessUtxo != null -> input.nonWitnessUtxo.txOut[txIn.outPoint.index.toInt()]
                input.witnessUtxo != null -> input.witnessUtxo
                else -> return Either.Left(UpdateFailure.CannotExtractTx("some utxos are missing"))
            }
            Pair(finalTxIn, txIn.outPoint to utxo)
        }.unzip()
        val finalTx = global.tx.copy(txIn = finalTxsIn)
        return try {
            Transaction.correctlySpends(finalTx, utxos.toMap(), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            Either.Right(finalTx)
        } catch (_: Exception) {
            Either.Left(UpdateFailure.CannotExtractTx("extracted transaction doesn't pass standard script validation"))
        }
    }

    private fun isFinal(input: PartiallySignedInput): Boolean {
        // Everything except the utxo, the scriptSigs and unknown keys must be empty.
        val emptied = input.redeemScript == null && input.witnessScript == null && input.partialSigs.isEmpty() && input.derivationPaths.isEmpty() && input.sighashType == null
        // And we must have complete scriptSig for either a witness or non-witness utxo.
        val hasWitnessData = input.witnessUtxo != null && input.scriptWitness != null
        val hasNonWitnessData = input.nonWitnessUtxo != null && input.scriptSig != null
        return emptied && (hasWitnessData || hasNonWitnessData)
    }

    /**
     * Compute the fees paid by the PSBT.
     * Note that if some inputs have not been updated yet, the fee cannot be computed.
     */
    public fun computeFees(): Satoshi? {
        val inputAmounts = inputs.zip(global.tx.txIn).map { (input, txIn) ->
            when {
                input.witnessUtxo != null -> input.witnessUtxo.amount
                input.nonWitnessUtxo != null -> input.nonWitnessUtxo.txOut[txIn.outPoint.index.toInt()].amount
                else -> null
            }
        }
        return when {
            inputAmounts.any { it == null } -> null
            else -> {
                val amountOut = global.tx.txOut.sumOf { it.amount.sat }.toSatoshi()
                val amountIn = inputAmounts.filterNotNull().sumOf { it.sat }.toSatoshi()
                amountIn - amountOut
            }
        }
    }

    public companion object {

        /** Only version 0 is supported for now. */
        public const val Version: Long = 0

        /**
         * @param prefix extended public key version bytes.
         * @param masterKeyFingerprint fingerprint of the master key.
         * @param extendedPublicKey BIP32 extended public key.
         */
        public data class ExtendedPublicKeyWithMaster(val prefix: Long, val masterKeyFingerprint: Long, val extendedPublicKey: DeterministicWallet.ExtendedPublicKey)

        /**
         * @param masterKeyFingerprint fingerprint of the master key.
         * @param keyPath bip 32 derivation path.
         */
        public data class KeyPathWithMaster(val masterKeyFingerprint: Long, val keyPath: KeyPath)

        public data class DataEntry(val key: ByteVector, val value: ByteVector)

        /**
         * Global data for the PSBT.
         *
         * @param version psbt version.
         * @param tx partially signed transaction. NB: the transaction must be serialized with the "old" format (without witnesses).
         * @param extendedPublicKeys (optional) extended public keys used when signing inputs and producing outputs.
         * @param unknown (optional) unknown global entries.
         */
        public data class Global(val version: Long, val tx: Transaction, val extendedPublicKeys: List<ExtendedPublicKeyWithMaster>, val unknown: List<DataEntry>)

        /**
         * A partially signed input. A valid PSBT must contain one such input per input of the [[Global.tx]].
         *
         * @param nonWitnessUtxo non-witness utxo, used when spending non-segwit outputs.
         * @param witnessUtxo witness utxo, used when spending segwit outputs.
         * @param sighashType sighash type to be used when producing signature for this output.
         * @param partialSigs signatures as would be pushed to the stack from a scriptSig or witness.
         * @param derivationPaths derivation paths used for the signatures.
         * @param redeemScript redeemScript for this input if it has one.
         * @param witnessScript witnessScript for this input if it has one.
         * @param scriptSig fully constructed scriptSig with signatures and any other scripts necessary for the input to pass validation.
         * @param scriptWitness fully constructed scriptWitness with signatures and any other scripts necessary for the input to pass validation.
         * @param ripemd160 preimages for ripemd160 miniscript challenges.
         * @param sha256 preimages for sha256 miniscript challenges.
         * @param hash160 preimages for hash160 miniscript challenges.
         * @param hash256 preimages for hash256 miniscript challenges.
         * @param unknown (optional) unknown global entries.
         */
        public data class PartiallySignedInput(
            val nonWitnessUtxo: Transaction?,
            val witnessUtxo: TxOut?,
            val sighashType: Int?,
            val partialSigs: Map<PublicKey, ByteVector>,
            val derivationPaths: Map<PublicKey, KeyPathWithMaster>,
            val redeemScript: List<ScriptElt>?,
            val witnessScript: List<ScriptElt>?,
            val scriptSig: List<ScriptElt>?,
            val scriptWitness: ScriptWitness?,
            val ripemd160: Set<ByteVector>,
            val sha256: Set<ByteVector>,
            val hash160: Set<ByteVector>,
            val hash256: Set<ByteVector>,
            val unknown: List<DataEntry>
        ) {
            public companion object {
                public val empty: PartiallySignedInput = PartiallySignedInput(null, null, null, mapOf(), mapOf(), null, null, null, null, setOf(), setOf(), setOf(), setOf(), listOf())
            }
        }

        /**
         * A partially signed output. A valid PSBT must contain one such output per output of the [[Global.tx]].
         *
         * @param redeemScript redeemScript for this output if it has one.
         * @param witnessScript witnessScript for this output if it has one.
         * @param derivationPaths derivation paths used to produce the public keys associated to this output.
         * @param unknown (optional) unknown global entries.
         */
        public data class PartiallySignedOutput(
            val redeemScript: List<ScriptElt>?,
            val witnessScript: List<ScriptElt>?,
            val derivationPaths: Map<PublicKey, KeyPathWithMaster>,
            val unknown: List<DataEntry>
        ) {
            public companion object {
                public val empty: PartiallySignedOutput = PartiallySignedOutput(null, null, mapOf(), listOf())
            }
        }

        public sealed class UpdateFailure {
            public data class InvalidInput(val reason: String) : UpdateFailure()
            public data class InvalidNonWitnessUtxo(val reason: String) : UpdateFailure()
            public data class InvalidWitnessUtxo(val reason: String) : UpdateFailure()
            public data class CannotCombine(val reason: String) : UpdateFailure()
            public data class CannotJoin(val reason: String) : UpdateFailure()
            public data class CannotFinalizeInput(val index: Int, val reason: String) : UpdateFailure()
            public data class CannotExtractTx(val reason: String) : UpdateFailure()
        }

        /**
         * Implements the PSBT combiner role: combines multiple psbts for the same unsigned transaction.
         *
         * @param psbts partially signed bitcoin transactions to combine.
         * @return a psbt that contains data from all the input psbts.
         */
        public fun combine(vararg psbts: Psbt): Either<UpdateFailure, Psbt> {
            return when {
                psbts.map { it.global.tx.txid }.toSet().size != 1 -> Either.Left(UpdateFailure.CannotCombine("cannot combine psbts for distinct transactions"))
                psbts.map { it.inputs.size }.toSet() != setOf(psbts[0].global.tx.txIn.size) -> Either.Left(UpdateFailure.CannotCombine("some psbts have an invalid number of inputs"))
                psbts.map { it.outputs.size }.toSet() != setOf(psbts[0].global.tx.txOut.size) -> Either.Left(UpdateFailure.CannotCombine("some psbts have an invalid number of outputs"))
                else -> {
                    val global = psbts[0].global.copy(
                        unknown = combineUnknown(psbts.map { it.global.unknown }),
                        extendedPublicKeys = combineExtendedPublicKeys(psbts.map { it.global.extendedPublicKeys })
                    )
                    val combined = Psbt(
                        global,
                        global.tx.txIn.indices.map { i -> combineInput(psbts.map { it.inputs[i] }) },
                        global.tx.txOut.indices.map { i -> combineOutput(psbts.map { it.outputs[i] }) }
                    )
                    Either.Right(combined)
                }
            }
        }

        private fun combineUnknown(unknowns: List<List<DataEntry>>): List<DataEntry> = unknowns.flatten().associateBy { it.key }.values.toList()

        private fun combineExtendedPublicKeys(keys: List<List<ExtendedPublicKeyWithMaster>>): List<ExtendedPublicKeyWithMaster> = keys.flatten().associateBy { it.extendedPublicKey }.values.toList()

        private fun combineInput(inputs: List<PartiallySignedInput>): PartiallySignedInput = PartiallySignedInput(
            inputs.mapNotNull { it.nonWitnessUtxo }.firstOrNull(),
            inputs.mapNotNull { it.witnessUtxo }.firstOrNull(),
            inputs.mapNotNull { it.sighashType }.firstOrNull(),
            inputs.flatMap { it.partialSigs.toList() }.toMap(),
            inputs.flatMap { it.derivationPaths.toList() }.toMap(),
            inputs.mapNotNull { it.redeemScript }.firstOrNull(),
            inputs.mapNotNull { it.witnessScript }.firstOrNull(),
            inputs.mapNotNull { it.scriptSig }.firstOrNull(),
            inputs.mapNotNull { it.scriptWitness }.firstOrNull(),
            inputs.flatMap { it.ripemd160 }.toSet(),
            inputs.flatMap { it.sha256 }.toSet(),
            inputs.flatMap { it.hash160 }.toSet(),
            inputs.flatMap { it.hash256 }.toSet(),
            combineUnknown(inputs.map { it.unknown })
        )

        private fun combineOutput(outputs: List<PartiallySignedOutput>): PartiallySignedOutput = PartiallySignedOutput(
            outputs.mapNotNull { it.redeemScript }.firstOrNull(),
            outputs.mapNotNull { it.witnessScript }.firstOrNull(),
            outputs.flatMap { it.derivationPaths.toList() }.toMap(),
            combineUnknown(outputs.map { it.unknown })
        )

        /**
         * Joins multiple distinct PSBTs with different inputs and outputs into one PSBT with inputs and outputs from all of
         * the PSBTs. No input in any of the PSBTs can be in more than one of the PSBTs.
         *
         * @param psbts partially signed bitcoin transactions to join.
         * @return a psbt that contains data from all the input psbts.
         */
        public fun join(vararg psbts: Psbt): Either<UpdateFailure, Psbt> {
            return when {
                psbts.isEmpty() -> Either.Left(UpdateFailure.CannotJoin("no psbt provided"))
                psbts.map { it.global.version }.toSet().size != 1 -> Either.Left(UpdateFailure.CannotJoin("cannot join psbts with different versions"))
                psbts.map { it.global.tx.version }.toSet().size != 1 -> Either.Left(UpdateFailure.CannotJoin("cannot join psbts with different tx versions"))
                psbts.map { it.global.tx.lockTime }.toSet().size != 1 -> Either.Left(UpdateFailure.CannotJoin("cannot join psbts with different tx lockTime"))
                psbts.any { it.global.tx.txIn.size != it.inputs.size || it.global.tx.txOut.size != it.outputs.size } -> Either.Left(UpdateFailure.CannotJoin("some psbts have an invalid number of inputs/outputs"))
                psbts.flatMap { it.global.tx.txIn.map { txIn -> txIn.outPoint } }.toSet().size != psbts.sumOf { it.global.tx.txIn.size } -> Either.Left(UpdateFailure.CannotJoin("cannot join psbts that spend the same input"))
                else -> {
                    val global = psbts[0].global.copy(
                        tx = psbts[0].global.tx.copy(
                            txIn = psbts.flatMap { it.global.tx.txIn },
                            txOut = psbts.flatMap { it.global.tx.txOut }
                        ),
                        extendedPublicKeys = psbts.flatMap { it.global.extendedPublicKeys }.distinct(),
                        unknown = psbts.flatMap { it.global.unknown }.distinct()
                    )
                    Either.Right(psbts[0].copy(
                        global = global,
                        inputs = psbts.flatMap { it.inputs },
                        outputs = psbts.flatMap { it.outputs }
                    ))
                }
            }
        }

        public fun write(psbt: Psbt): ByteVector {
            val output = ByteArrayOutput()
            write(psbt, output)
            return ByteVector(output.toByteArray())
        }

        public fun write(psbt: Psbt, out: Output) {
            /********** Magic header **********/
            out.write(0x70)
            out.write(0x73)
            out.write(0x62)
            out.write(0x74)
            out.write(0xff)

            /********** Global types **********/
            writeDataEntry(DataEntry(ByteVector("00"), ByteVector(Transaction.write(psbt.global.tx, Protocol.PROTOCOL_VERSION or Transaction.SERIALIZE_TRANSACTION_NO_WITNESS))), out)
            psbt.global.extendedPublicKeys.forEach { xpub ->
                val key = ByteArrayOutput()
                key.write(0x01) // <keytype>
                Pack.writeInt32BE(xpub.prefix.toInt(), key)
                DeterministicWallet.write(xpub.extendedPublicKey, key)
                val value = ByteArrayOutput()
                Pack.writeInt32BE(xpub.masterKeyFingerprint.toInt(), value)
                xpub.extendedPublicKey.path.path.forEach { child -> Pack.writeInt32LE(child.toInt(), value) }
                writeDataEntry(DataEntry(ByteVector(key.toByteArray()), ByteVector(value.toByteArray())), out)
            }
            if (psbt.global.version > 0) {
                writeDataEntry(DataEntry(ByteVector("fb"), ByteVector(Pack.writeInt32LE(psbt.global.version.toInt()))), out)
            }
            psbt.global.unknown.forEach { writeDataEntry(it, out) }
            out.write(0x00) // separator

            /********** Inputs **********/
            psbt.inputs.forEach { input ->
                input.nonWitnessUtxo?.let { writeDataEntry(DataEntry(ByteVector("00"), ByteVector(Transaction.write(it))), out) }
                input.witnessUtxo?.let { writeDataEntry(DataEntry(ByteVector("01"), ByteVector(TxOut.write(it))), out) }
                sortPublicKeys(input.partialSigs).forEach { (publicKey, signature) -> writeDataEntry(DataEntry(ByteVector("02") + publicKey.value, signature), out) }
                input.sighashType?.let { writeDataEntry(DataEntry(ByteVector("03"), ByteVector(Pack.writeInt32LE(it))), out) }
                input.redeemScript?.let { writeDataEntry(DataEntry(ByteVector("04"), ByteVector(Script.write(it))), out) }
                input.witnessScript?.let { writeDataEntry(DataEntry(ByteVector("05"), ByteVector(Script.write(it))), out) }
                sortPublicKeys(input.derivationPaths).forEach { (publicKey, path) ->
                    val key = ByteVector("06") + publicKey.value
                    val value = ByteVector(Pack.writeInt32BE(path.masterKeyFingerprint.toInt())).concat(path.keyPath.path.map { ByteVector(Pack.writeInt32LE(it.toInt())) })
                    writeDataEntry(DataEntry(key, value), out)
                }
                input.scriptSig?.let { writeDataEntry(DataEntry(ByteVector("07"), ByteVector(Script.write(it))), out) }
                input.scriptWitness?.let { writeDataEntry(DataEntry(ByteVector("08"), ByteVector(ScriptWitness.write(it))), out) }
                input.ripemd160.forEach { writeDataEntry(DataEntry(ByteVector("0a") + Crypto.ripemd160(it), it), out) }
                input.sha256.forEach { writeDataEntry(DataEntry(ByteVector("0b") + Crypto.sha256(it), it), out) }
                input.hash160.forEach { writeDataEntry(DataEntry(ByteVector("0c") + Crypto.hash160(it), it), out) }
                input.hash256.forEach { writeDataEntry(DataEntry(ByteVector("0d") + Crypto.hash256(it), it), out) }
                input.unknown.forEach { writeDataEntry(it, out) }
                out.write(0x00) // separator
            }

            /********** Outputs **********/
            psbt.outputs.forEach { output ->
                output.redeemScript?.let { writeDataEntry(DataEntry(ByteVector("00"), ByteVector(Script.write(it))), out) }
                output.witnessScript?.let { writeDataEntry(DataEntry(ByteVector("01"), ByteVector(Script.write(it))), out) }
                sortPublicKeys(output.derivationPaths).forEach { (publicKey, path) ->
                    val key = ByteVector("02") + publicKey.value
                    val value = ByteVector(Pack.writeInt32BE(path.masterKeyFingerprint.toInt())).concat(path.keyPath.path.map { ByteVector(Pack.writeInt32LE(it.toInt())) })
                    writeDataEntry(DataEntry(key, value), out)
                }
                output.unknown.forEach { writeDataEntry(it, out) }
                out.write(0x00) // separator
            }
        }

        /** We use lexicographic ordering on the public keys. */
        private fun <T> sortPublicKeys(publicKeys: Map<PublicKey, T>): List<Pair<PublicKey, T>> {
            return publicKeys.toList().sortedWith { a, b -> LexicographicalOrdering.compare(a.first, b.first) }
        }

        private fun writeDataEntry(entry: DataEntry, output: Output) {
            BtcSerializer.writeVarint(entry.key.size(), output)
            output.write(entry.key.bytes)
            BtcSerializer.writeVarint(entry.value.size(), output)
            output.write(entry.value.bytes)
        }

        public sealed class ParseFailure {
            public object InvalidMagicBytes : ParseFailure()
            public object InvalidSeparator : ParseFailure()
            public object DuplicateKeys : ParseFailure()
            public data class InvalidPsbtVersion(val reason: String) : ParseFailure()
            public data class UnsupportedPsbtVersion(val version: Long) : ParseFailure()
            public data class InvalidGlobalTx(val reason: String) : ParseFailure()
            public object GlobalTxMissing : ParseFailure()
            public data class InvalidExtendedPublicKey(val reason: String) : ParseFailure()
            public data class InvalidTxInput(val reason: String) : ParseFailure()
            public data class InvalidTxOutput(val reason: String) : ParseFailure()
            public object InvalidContent : ParseFailure()
        }

        public fun read(input: ByteVector): Either<ParseFailure, Psbt> = read(ByteArrayInput(input.toByteArray()))
        public fun read(input: ByteArray): Either<ParseFailure, Psbt> = read(ByteArrayInput(input))
        public fun read(input: Input): Either<ParseFailure, Psbt> {
            /********** Magic header **********/
            if (input.read() != 0x70 || input.read() != 0x73 || input.read() != 0x62 || input.read() != 0x74) {
                return Either.Left(ParseFailure.InvalidMagicBytes)
            }
            if (input.read() != 0xff) {
                return Either.Left(ParseFailure.InvalidSeparator)
            }

            /********** Global types **********/
            val global = run {
                val globalMap = readDataMap(input).getOrElse {
                    return when (it) {
                        is ReadEntryFailure.DuplicateKeys -> Either.Left(ParseFailure.DuplicateKeys)
                        else -> Either.Left(ParseFailure.InvalidContent)
                    }
                }
                val keyTypes = setOf(0x00.toByte(), 0x01.toByte(), 0xfb.toByte())
                val (known, unknown) = globalMap.partition { keyTypes.contains(it.key[0]) }
                val version = known.find { it.key[0] == 0xfb.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidPsbtVersion("version key must contain exactly 1 byte"))
                        it.value.size() != 4 -> return Either.Left(ParseFailure.InvalidPsbtVersion("version must contain exactly 4 bytes"))
                        else -> {
                            val v = Pack.int32LE(it.value.bytes).toUInt().toLong()
                            when {
                                v > Version -> return Either.Left(ParseFailure.UnsupportedPsbtVersion(v))
                                else -> v
                            }
                        }
                    }
                } ?: 0L
                val tx = known.find { it.key[0] == 0x00.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidGlobalTx("global tx key must contain exactly 1 byte"))
                        else -> {
                            val tx = try {
                                Transaction.read(it.value.bytes, Protocol.PROTOCOL_VERSION or Transaction.SERIALIZE_TRANSACTION_NO_WITNESS)
                            } catch (e: Exception) {
                                return Either.Left(ParseFailure.InvalidGlobalTx(e.message ?: "failed to parse transaction"))
                            }
                            when {
                                tx.txIn.any { input -> input.hasWitness || !input.signatureScript.isEmpty() } -> return Either.Left(ParseFailure.InvalidGlobalTx("global tx inputs must have empty scriptSigs and witness"))
                                else -> tx
                            }
                        }
                    }
                } ?: return Either.Left(ParseFailure.GlobalTxMissing)
                val xpubs = known.filter { it.key[0] == 0x01.toByte() }.map {
                    when {
                        it.key.size() != 79 -> return Either.Left(ParseFailure.InvalidExtendedPublicKey("<xpub> must contain 78 bytes"))
                        else -> {
                            val xpub = ByteArrayInput(it.key.drop(1).toByteArray())
                            val prefix = Pack.int32BE(xpub).toUInt().toLong()
                            val depth = xpub.read()
                            val parent = Pack.int32BE(xpub).toUInt().toLong()
                            val childNumber = Pack.int32BE(xpub).toUInt().toLong()
                            val chainCode = ByteVector32(xpub.readNBytes(32)!!)
                            val publicKey = ByteVector(xpub.readNBytes(33)!!)
                            when {
                                it.value.size() != 4 * (depth + 1) -> return Either.Left(ParseFailure.InvalidExtendedPublicKey("<xpub> must contain the master key fingerprint and derivation path"))
                                else -> {
                                    val masterKeyFingerprint = Pack.int32BE(it.value.take(4).toByteArray()).toUInt().toLong()
                                    val derivationPath = KeyPath((0 until depth).map { i -> Pack.int32LE(it.value.slice(4 * (i + 1), 4 * (i + 2)).toByteArray()).toUInt().toLong() })
                                    when {
                                        derivationPath.lastChildNumber != childNumber -> return Either.Left(ParseFailure.InvalidExtendedPublicKey("<xpub> last child number mismatch"))
                                        else -> ExtendedPublicKeyWithMaster(prefix, masterKeyFingerprint, DeterministicWallet.ExtendedPublicKey(publicKey, chainCode, depth, derivationPath, parent))
                                    }
                                }
                            }
                        }
                    }
                }
                Global(version, tx, xpubs, unknown)
            }

            /********** Inputs **********/
            val inputs = global.tx.txIn.map { txIn ->
                val keyTypes = setOf<Byte>(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c, 0x0d)
                val entries = readDataMap(input).getOrElse {
                    return when (it) {
                        is ReadEntryFailure.DuplicateKeys -> Either.Left(ParseFailure.DuplicateKeys)
                        else -> Either.Left(ParseFailure.InvalidContent)
                    }
                }
                val (known, unknown) = entries.partition { keyTypes.contains(it.key[0]) }
                val nonWitnessUtxo = known.find { it.key[0] == 0x00.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxInput("non-witness utxo key must contain exactly 1 byte"))
                        else -> {
                            val inputTx = try {
                                Transaction.read(it.value.bytes)
                            } catch (e: Exception) {
                                return Either.Left(ParseFailure.InvalidTxInput(e.message ?: "failed to parse transaction"))
                            }
                            when {
                                inputTx.txid != txIn.outPoint.txid || txIn.outPoint.index >= inputTx.txOut.size -> return Either.Left(ParseFailure.InvalidTxInput("non-witness utxo does not match psbt outpoint"))
                                else -> inputTx
                            }
                        }
                    }
                }
                val witnessUtxo = known.find { it.key[0] == 0x01.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxInput("witness utxo key must contain exactly 1 byte"))
                        else -> {
                            try {
                                TxOut.read(it.value.bytes)
                            } catch (e: Exception) {
                                return Either.Left(ParseFailure.InvalidTxInput(e.message ?: "failed to parse transaction output"))
                            }
                        }
                    }
                }
                val partialSigs = known.filter { it.key[0] == 0x02.toByte() }.map {
                    when {
                        it.key.size() != 34 -> return Either.Left(ParseFailure.InvalidTxInput("public key must contain exactly 33 bytes"))
                        else -> PublicKey(it.key.drop(1)) to it.value
                    }
                }.toMap()
                val sighashType = known.find { it.key[0] == 0x03.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxInput("sighash type key must contain exactly 1 byte"))
                        it.value.size() != 4 -> return Either.Left(ParseFailure.InvalidTxInput("sighash type must contain exactly 4 bytes"))
                        else -> Pack.int32LE(it.value.bytes)
                    }
                }
                val redeemScript = known.find { it.key[0] == 0x04.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxInput("redeem script key must contain exactly 1 byte"))
                        else -> runCatching { Script.parse(it.value) }.getOrElse { return Either.Left(ParseFailure.InvalidTxInput("failed to parse redeem script")) }
                    }
                }
                val witnessScript = known.find { it.key[0] == 0x05.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxInput("witness script key must contain exactly 1 byte"))
                        else -> runCatching { Script.parse(it.value) }.getOrElse { return Either.Left(ParseFailure.InvalidTxInput("failed to parse witness script")) }
                    }
                }
                val derivationPaths = known.filter { it.key[0] == 0x06.toByte() }.map {
                    when {
                        it.key.size() != 34 -> return Either.Left(ParseFailure.InvalidTxInput("bip32 derivation public key must contain exactly 33 bytes"))
                        it.value.size() < 4 || it.value.size() % 4 != 0 -> return Either.Left(ParseFailure.InvalidTxInput("bip32 derivation must contain master key fingerprint and child indexes"))
                        else -> {
                            val publicKey = PublicKey(it.key.drop(1))
                            val masterKeyFingerprint = Pack.int32BE(it.value.take(4).toByteArray()).toUInt().toLong()
                            val childCount = (it.value.size() / 4) - 1
                            val derivationPath = KeyPath((0 until childCount).map { i -> Pack.int32LE(it.value.slice(4 * (i + 1), 4 * (i + 2)).toByteArray()).toUInt().toLong() })
                            publicKey to KeyPathWithMaster(masterKeyFingerprint, derivationPath)
                        }
                    }
                }.toMap()
                val scriptSig = known.find { it.key[0] == 0x07.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxInput("script sig key must contain exactly 1 byte"))
                        else -> runCatching { Script.parse(it.value) }.getOrElse { return Either.Left(ParseFailure.InvalidTxInput("failed to parse script sig")) }
                    }
                }
                val scriptWitness = known.find { it.key[0] == 0x08.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxInput("script witness key must contain exactly 1 byte"))
                        else -> try {
                            ScriptWitness.read(it.value.bytes)
                        } catch (e: Exception) {
                            return Either.Left(ParseFailure.InvalidTxInput(e.message ?: "failed to parse script witness"))
                        }
                    }
                }
                val ripemd160Preimages = known.filter { it.key[0] == 0x0a.toByte() }.map {
                    when {
                        it.key.size() != 21 -> return Either.Left(ParseFailure.InvalidTxInput("ripemd160 hash must contain exactly 20 bytes"))
                        !it.key.drop(1).contentEquals(Crypto.ripemd160(it.value)) -> return Either.Left(ParseFailure.InvalidTxInput("invalid ripemd160 preimage"))
                        else -> it.value
                    }
                }.toSet()
                val sha256Preimages = known.filter { it.key[0] == 0x0b.toByte() }.map {
                    when {
                        it.key.size() != 33 -> return Either.Left(ParseFailure.InvalidTxInput("sha256 hash must contain exactly 32 bytes"))
                        !it.key.drop(1).contentEquals(Crypto.sha256(it.value)) -> return Either.Left(ParseFailure.InvalidTxInput("invalid sha256 preimage"))
                        else -> it.value
                    }
                }.toSet()
                val hash160Preimages = known.filter { it.key[0] == 0x0c.toByte() }.map {
                    when {
                        it.key.size() != 21 -> return Either.Left(ParseFailure.InvalidTxInput("hash160 hash must contain exactly 20 bytes"))
                        !it.key.drop(1).contentEquals(Crypto.hash160(it.value)) -> return Either.Left(ParseFailure.InvalidTxInput("invalid hash160 preimage"))
                        else -> it.value
                    }
                }.toSet()
                val hash256Preimages = known.filter { it.key[0] == 0x0d.toByte() }.map {
                    when {
                        it.key.size() != 33 -> return Either.Left(ParseFailure.InvalidTxInput("hash256 hash must contain exactly 32 bytes"))
                        !it.key.drop(1).contentEquals(Crypto.hash256(it.value)) -> return Either.Left(ParseFailure.InvalidTxInput("invalid hash256 preimage"))
                        else -> it.value
                    }
                }.toSet()
                PartiallySignedInput(
                    nonWitnessUtxo,
                    witnessUtxo,
                    sighashType,
                    partialSigs,
                    derivationPaths,
                    redeemScript,
                    witnessScript,
                    scriptSig,
                    scriptWitness,
                    ripemd160Preimages,
                    sha256Preimages,
                    hash160Preimages,
                    hash256Preimages,
                    unknown
                )
            }

            /********** Outputs **********/
            val outputs = global.tx.txOut.map {
                val keyTypes = setOf<Byte>(0x00, 0x01, 0x02)
                val entries = readDataMap(input).getOrElse {
                    return when (it) {
                        is ReadEntryFailure.DuplicateKeys -> Either.Left(ParseFailure.DuplicateKeys)
                        else -> Either.Left(ParseFailure.InvalidContent)
                    }
                }
                val (known, unknown) = entries.partition { keyTypes.contains(it.key[0]) }
                val redeemScript = known.find { it.key[0] == 0x00.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxOutput("redeem script key must contain exactly 1 byte"))
                        else -> runCatching { Script.parse(it.value) }.getOrElse { return Either.Left(ParseFailure.InvalidTxOutput("failed to parse redeem script")) }
                    }
                }
                val witnessScript = known.find { it.key[0] == 0x01.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return Either.Left(ParseFailure.InvalidTxOutput("witness script key must contain exactly 1 byte"))
                        else -> runCatching { Script.parse(it.value) }.getOrElse { return Either.Left(ParseFailure.InvalidTxOutput("failed to parse witness script")) }
                    }
                }
                val derivationPaths = known.filter { it.key[0] == 0x02.toByte() }.map {
                    when {
                        it.key.size() != 34 -> return Either.Left(ParseFailure.InvalidTxOutput("bip32 derivation public key must contain exactly 33 bytes"))
                        it.value.size() < 4 || it.value.size() % 4 != 0 -> return Either.Left(ParseFailure.InvalidTxOutput("bip32 derivation must contain master key fingerprint and child indexes"))
                        else -> {
                            val publicKey = PublicKey(it.key.drop(1))
                            val masterKeyFingerprint = Pack.int32BE(it.value.take(4).toByteArray()).toUInt().toLong()
                            val childCount = (it.value.size() / 4) - 1
                            val derivationPath = KeyPath((0 until childCount).map { i -> Pack.int32LE(it.value.slice(4 * (i + 1), 4 * (i + 2)).toByteArray()).toUInt().toLong() })
                            publicKey to KeyPathWithMaster(masterKeyFingerprint, derivationPath)
                        }
                    }
                }.toMap()
                PartiallySignedOutput(redeemScript, witnessScript, derivationPaths, unknown)
            }

            return if (input.availableBytes != 0) {
                Either.Left(ParseFailure.InvalidContent)
            } else {
                Either.Right(Psbt(global, inputs, outputs))
            }
        }

        private sealed class ReadEntryFailure {
            object DuplicateKeys : ReadEntryFailure()
            object InvalidData : ReadEntryFailure()
            object EndOfDataMap : ReadEntryFailure()
        }

        private fun readDataMap(input: Input, entries: List<DataEntry> = listOf()): Either<ReadEntryFailure, List<DataEntry>> {
            return when (val result = readDataEntry(input)) {
                is Either.Right -> readDataMap(input, entries + result.value)
                is Either.Left -> when (result.value) {
                    is ReadEntryFailure.EndOfDataMap -> {
                        if (entries.map { it.key }.toSet().size != entries.size) {
                            Either.Left(ReadEntryFailure.DuplicateKeys)
                        } else {
                            Either.Right(entries)
                        }
                    }
                    is ReadEntryFailure.InvalidData -> Either.Left(ReadEntryFailure.InvalidData)
                    else -> Either.Left(result.value)
                }
            }
        }

        private fun readDataEntry(input: Input): Either<ReadEntryFailure, DataEntry> {
            if (input.availableBytes == 0) return Either.Left(ReadEntryFailure.InvalidData)
            val keyLength = BtcSerializer.varint(input).toInt()
            if (keyLength == 0) return Either.Left(ReadEntryFailure.EndOfDataMap)
            val key = input.readNBytes(keyLength) ?: return Either.Left(ReadEntryFailure.InvalidData)

            if (input.availableBytes == 0) return Either.Left(ReadEntryFailure.InvalidData)
            val valueLength = BtcSerializer.varint(input).toInt()
            val value = input.readNBytes(valueLength) ?: return Either.Left(ReadEntryFailure.InvalidData)

            return Either.Right(DataEntry(ByteVector(key), ByteVector(value)))
        }
    }

}