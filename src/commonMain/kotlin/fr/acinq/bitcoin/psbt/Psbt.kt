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

package fr.acinq.bitcoin.psbt

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.Pack
import fr.acinq.bitcoin.io.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.bitcoin.utils.getOrElse
import kotlin.jvm.JvmStatic

/**
 * A partially signed bitcoin transaction: see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki.
 *
 * @param global global psbt data containing the transaction to be signed.
 * @param inputs signing data for each input of the transaction to be signed (order matches the unsigned tx).
 * @param outputs signing data for each output of the transaction to be signed (order matches the unsigned tx).
 */
@OptIn(ExperimentalUnsignedTypes::class)
public data class Psbt(val global: Global, val inputs: List<Input>, val outputs: List<Output>) {

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
        tx.txIn.map { Input.PartiallySignedInputWithoutUtxo(null, mapOf(), setOf(), setOf(), setOf(), setOf(), listOf()) },
        tx.txOut.map { Output.UnspecifiedOutput(mapOf(), listOf()) }
    )

    /**
     * Implements the PSBT updater role; adds information about a given segwit utxo.
     * When you have access to the complete input transaction, you should prefer [[updateWitnessInputTx]].
     *
     * @param outPoint utxo being spent.
     * @param txOut transaction output for the provided outPoint.
     * @param redeemScript redeem script if known and applicable (when using p2sh-embedded segwit).
     * @param witnessScript witness script if known and applicable (when using p2wsh).
     * @param sighashType sighash type if one should be specified.
     * @param derivationPaths derivation paths for keys used by this utxo.
     * @return psbt with the matching input updated.
     */
    public fun updateWitnessInput(
        outPoint: OutPoint,
        txOut: TxOut,
        redeemScript: List<ScriptElt>? = null,
        witnessScript: List<ScriptElt>? = null,
        sighashType: Int? = null,
        derivationPaths: Map<PublicKey, KeyPathWithMaster> = mapOf()
    ): Either<UpdateFailure, Psbt> {
        val inputIndex = global.tx.txIn.indexOfFirst { it.outPoint == outPoint }
        if (inputIndex < 0) return Either.Left(UpdateFailure.InvalidInput("psbt transaction does not spend the provided outpoint"))
        val updatedInput = when (val input = inputs[inputIndex]) {
            is Input.PartiallySignedInputWithoutUtxo -> Input.WitnessInput.PartiallySignedWitnessInput(
                txOut,
                null,
                sighashType ?: input.sighashType,
                mapOf(),
                derivationPaths + input.derivationPaths,
                redeemScript,
                witnessScript,
                input.ripemd160,
                input.sha256,
                input.hash160,
                input.hash256,
                input.unknown
            )
            is Input.WitnessInput.PartiallySignedWitnessInput -> input.copy(
                txOut = txOut,
                redeemScript = redeemScript ?: input.redeemScript,
                witnessScript = witnessScript ?: input.witnessScript,
                sighashType = sighashType ?: input.sighashType,
                derivationPaths = input.derivationPaths + derivationPaths
            )
            is Input.NonWitnessInput.PartiallySignedNonWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update segwit input: it has already been updated with non-segwit data"))
            is Input.FinalizedInputWithoutUtxo -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update segwit input: it has already been finalized"))
            is Input.WitnessInput.FinalizedWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update segwit input: it has already been finalized"))
            is Input.NonWitnessInput.FinalizedNonWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update segwit input: it has already been finalized"))
        }
        return Either.Right(this.copy(inputs = inputs.updated(inputIndex, updatedInput)))
    }

    /**
     * Implements the PSBT updater role; adds information about a given segwit utxo.
     * Note that we always fill the nonWitnessUtxo (see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#cite_note-7).
     *
     * @param inputTx transaction containing the utxo.
     * @param outputIndex index of the utxo in the inputTx.
     * @param redeemScript redeem script if known and applicable (when using p2sh-embedded segwit).
     * @param witnessScript witness script if known and applicable (when using p2wsh).
     * @param sighashType sighash type if one should be specified.
     * @param derivationPaths derivation paths for keys used by this utxo.
     * @return psbt with the matching input updated.
     */
    public fun updateWitnessInputTx(
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
        val updatedInput = when (val input = inputs[inputIndex]) {
            is Input.PartiallySignedInputWithoutUtxo -> Input.WitnessInput.PartiallySignedWitnessInput(
                inputTx.txOut[outputIndex],
                inputTx,
                sighashType ?: input.sighashType,
                mapOf(),
                derivationPaths + input.derivationPaths,
                redeemScript,
                witnessScript,
                input.ripemd160,
                input.sha256,
                input.hash160,
                input.hash256,
                input.unknown
            )
            is Input.WitnessInput.PartiallySignedWitnessInput -> input.copy(
                txOut = inputTx.txOut[outputIndex],
                nonWitnessUtxo = inputTx,
                redeemScript = redeemScript ?: input.redeemScript,
                witnessScript = witnessScript ?: input.witnessScript,
                sighashType = sighashType ?: input.sighashType,
                derivationPaths = input.derivationPaths + derivationPaths
            )
            is Input.NonWitnessInput.PartiallySignedNonWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update segwit input: it has already been updated with non-segwit data"))
            is Input.FinalizedInputWithoutUtxo -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update segwit input: it has already been finalized"))
            is Input.WitnessInput.FinalizedWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update segwit input: it has already been finalized"))
            is Input.NonWitnessInput.FinalizedNonWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update segwit input: it has already been finalized"))
        }
        return Either.Right(this.copy(inputs = inputs.updated(inputIndex, updatedInput)))
    }

    /**
     * Implements the PSBT updater role; adds information about a given non-segwit utxo.
     *
     * @param inputTx transaction containing the utxo.
     * @param outputIndex index of the utxo in the inputTx.
     * @param redeemScript redeem script if known and applicable (when using p2sh).
     * @param sighashType sighash type if one should be specified.
     * @param derivationPaths derivation paths for keys used by this utxo.
     * @return psbt with the matching input updated.
     */
    public fun updateNonWitnessInput(
        inputTx: Transaction,
        outputIndex: Int,
        redeemScript: List<ScriptElt>? = null,
        sighashType: Int? = null,
        derivationPaths: Map<PublicKey, KeyPathWithMaster> = mapOf()
    ): Either<UpdateFailure, Psbt> {
        if (outputIndex >= inputTx.txOut.size) return Either.Left(UpdateFailure.InvalidInput("output index must exist in the input tx"))
        val outpoint = OutPoint(inputTx, outputIndex.toLong())
        val inputIndex = global.tx.txIn.indexOfFirst { it.outPoint == outpoint }
        if (inputIndex < 0) return Either.Left(UpdateFailure.InvalidInput("psbt transaction does not spend the provided outpoint"))
        val updatedInput = when (val input = inputs[inputIndex]) {
            is Input.PartiallySignedInputWithoutUtxo -> Input.NonWitnessInput.PartiallySignedNonWitnessInput(
                inputTx,
                outputIndex,
                sighashType ?: input.sighashType,
                mapOf(),
                derivationPaths + input.derivationPaths,
                redeemScript,
                input.ripemd160,
                input.sha256,
                input.hash160,
                input.hash256,
                input.unknown
            )
            is Input.NonWitnessInput.PartiallySignedNonWitnessInput -> input.copy(
                inputTx = inputTx,
                outputIndex = outputIndex,
                redeemScript = redeemScript ?: input.redeemScript,
                sighashType = sighashType ?: input.sighashType,
                derivationPaths = input.derivationPaths + derivationPaths
            )
            is Input.WitnessInput.PartiallySignedWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update non-segwit input: it has already been updated with segwit data"))
            is Input.FinalizedInputWithoutUtxo -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update non-segwit input: it has already been finalized"))
            is Input.WitnessInput.FinalizedWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update non-segwit input: it has already been finalized"))
            is Input.NonWitnessInput.FinalizedNonWitnessInput -> return Either.Left(UpdateFailure.CannotUpdateInput(inputIndex, "cannot update non-segwit input: it has already been finalized"))
        }
        return Either.Right(this.copy(inputs = inputs.updated(inputIndex, updatedInput)))
    }

    public fun updatePreimageChallenges(outPoint: OutPoint, ripemd160: Set<ByteVector>, sha256: Set<ByteVector>, hash160: Set<ByteVector>, hash256: Set<ByteVector>): Either<UpdateFailure, Psbt> {
        val inputIndex = global.tx.txIn.indexOfFirst { it.outPoint == outPoint }
        if (inputIndex < 0) return Either.Left(UpdateFailure.InvalidInput("psbt transaction does not spend the provided outpoint"))
        return updatePreimageChallenges(inputIndex, ripemd160, sha256, hash160, hash256)
    }

    public fun updatePreimageChallenges(inputIndex: Int, ripemd160: Set<ByteVector>, sha256: Set<ByteVector>, hash160: Set<ByteVector>, hash256: Set<ByteVector>): Either<UpdateFailure, Psbt> {
        if (inputIndex >= inputs.size) return Either.Left(UpdateFailure.InvalidInput("input index must exist in the input tx"))
        val updatedInput = when (val input = inputs[inputIndex]) {
            is Input.PartiallySignedInputWithoutUtxo -> input.copy(ripemd160 = ripemd160 + input.ripemd160, sha256 = sha256 + input.sha256, hash160 = hash160 + input.hash160, hash256 = hash256 + input.hash256)
            is Input.WitnessInput.PartiallySignedWitnessInput -> input.copy(ripemd160 = ripemd160 + input.ripemd160, sha256 = sha256 + input.sha256, hash160 = hash160 + input.hash160, hash256 = hash256 + input.hash256)
            is Input.NonWitnessInput.PartiallySignedNonWitnessInput -> input.copy(ripemd160 = ripemd160 + input.ripemd160, sha256 = sha256 + input.sha256, hash160 = hash160 + input.hash160, hash256 = hash256 + input.hash256)
            is Input.WitnessInput.FinalizedWitnessInput -> input.copy(ripemd160 = ripemd160 + input.ripemd160, sha256 = sha256 + input.sha256, hash160 = hash160 + input.hash160, hash256 = hash256 + input.hash256)
            is Input.NonWitnessInput.FinalizedNonWitnessInput -> input.copy(ripemd160 = ripemd160 + input.ripemd160, sha256 = sha256 + input.sha256, hash160 = hash160 + input.hash160, hash256 = hash256 + input.hash256)
            is Input.FinalizedInputWithoutUtxo -> input.copy(ripemd160 = ripemd160 + input.ripemd160, sha256 = sha256 + input.sha256, hash160 = hash160 + input.hash160, hash256 = hash256 + input.hash256)
        }
        return Either.Right(this.copy(inputs = inputs.updated(inputIndex, updatedInput)))
    }

    /**
     * Add details for a segwit output.
     *
     * @param outputIndex index of the output in the psbt.
     * @param witnessScript witness script if known and applicable (when using p2wsh).
     * @param redeemScript redeem script if known and applicable (when using p2sh-embedded segwit).
     * @param derivationPaths derivation paths for keys used by this output.
     * @return psbt with the matching output updated.
     */
    public fun updateWitnessOutput(
        outputIndex: Int,
        witnessScript: List<ScriptElt>? = null,
        redeemScript: List<ScriptElt>? = null,
        derivationPaths: Map<PublicKey, KeyPathWithMaster> = mapOf()
    ): Either<UpdateFailure, Psbt> {
        if (outputIndex >= global.tx.txOut.size) return Either.Left(UpdateFailure.InvalidInput("output index must exist in the global tx"))
        val updatedOutput = when (val output = outputs[outputIndex]) {
            is Output.NonWitnessOutput -> return Either.Left(UpdateFailure.CannotUpdateOutput(outputIndex, "cannot update segwit output: it has already been updated with non-segwit data"))
            is Output.WitnessOutput -> output.copy(
                witnessScript = witnessScript ?: output.witnessScript,
                redeemScript = redeemScript ?: output.redeemScript,
                derivationPaths = derivationPaths + output.derivationPaths
            )
            is Output.UnspecifiedOutput -> Output.WitnessOutput(witnessScript, redeemScript, derivationPaths + output.derivationPaths, output.unknown)
        }
        return Either.Right(this.copy(outputs = outputs.updated(outputIndex, updatedOutput)))
    }

    /**
     * Add details for a non-segwit output.
     *
     * @param outputIndex index of the output in the psbt.
     * @param redeemScript redeem script if known and applicable (when using p2sh).
     * @param derivationPaths derivation paths for keys used by this output.
     * @return psbt with the matching output updated.
     */
    public fun updateNonWitnessOutput(
        outputIndex: Int,
        redeemScript: List<ScriptElt>? = null,
        derivationPaths: Map<PublicKey, KeyPathWithMaster> = mapOf()
    ): Either<UpdateFailure, Psbt> {
        if (outputIndex >= global.tx.txOut.size) return Either.Left(UpdateFailure.InvalidInput("output index must exist in the global tx"))
        val updatedOutput = when (val output = outputs[outputIndex]) {
            is Output.NonWitnessOutput -> output.copy(
                redeemScript = redeemScript ?: output.redeemScript,
                derivationPaths = derivationPaths + output.derivationPaths
            )
            is Output.WitnessOutput -> return Either.Left(UpdateFailure.CannotUpdateOutput(outputIndex, "cannot update non-segwit output: it has already been updated with segwit data"))
            is Output.UnspecifiedOutput -> Output.NonWitnessOutput(redeemScript, derivationPaths + output.derivationPaths, output.unknown)
        }
        return Either.Right(this.copy(outputs = outputs.updated(outputIndex, updatedOutput)))
    }

    /**
     * Implements the PSBT signer role: sign a given input.
     * The caller needs to carefully verify that it wants to spend that input, and that the unsigned transaction matches
     * what it expects.
     *
     * @param priv private key used to sign the input.
     * @param outPoint input that should be signed.
     * @return the psbt with a partial signature added (other inputs will not be modified).
     */
    public fun sign(priv: PrivateKey, outPoint: OutPoint): Either<UpdateFailure, SignPsbtResult> {
        val inputIndex = global.tx.txIn.indexOfFirst { it.outPoint == outPoint }
        if (inputIndex < 0) return Either.Left(UpdateFailure.InvalidInput("psbt transaction does not spend the provided outpoint"))
        return sign(priv, inputIndex)
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
    public fun sign(priv: PrivateKey, inputIndex: Int): Either<UpdateFailure, SignPsbtResult> {
        if (inputIndex >= inputs.size) return Either.Left(UpdateFailure.InvalidInput("input index must exist in the input tx"))
        val input = inputs[inputIndex]
        return sign(priv, inputIndex, input, global).map { SignPsbtResult(this.copy(inputs = inputs.updated(inputIndex, it.first)), it.second) }
    }

    private fun sign(priv: PrivateKey, inputIndex: Int, input: Input, global: Global): Either<UpdateFailure, Pair<Input, ByteVector>> {
        val txIn = global.tx.txIn[inputIndex]
        return when (input) {
            is Input.PartiallySignedInputWithoutUtxo -> Either.Left(UpdateFailure.CannotSignInput(inputIndex, "cannot sign: input hasn't been updated with utxo data"))
            is Input.WitnessInput.PartiallySignedWitnessInput -> {
                if (input.nonWitnessUtxo != null && input.nonWitnessUtxo!!.txid != txIn.outPoint.txid) {
                    Either.Left(UpdateFailure.InvalidNonWitnessUtxo("non-witness utxo does not match unsigned tx input"))
                } else if (input.nonWitnessUtxo != null && input.nonWitnessUtxo!!.txOut.size <= txIn.outPoint.index) {
                    Either.Left(UpdateFailure.InvalidNonWitnessUtxo("non-witness utxo index out of bounds"))
                } else if (!Script.isNativeWitnessScript(input.txOut.publicKeyScript) && !Script.isPayToScript(input.txOut.publicKeyScript.toByteArray())) {
                    Either.Left(UpdateFailure.InvalidWitnessUtxo("witness utxo must use native segwit or P2SH embedded segwit"))
                } else {
                    signWitness(priv, inputIndex, input, global)
                }
            }
            is Input.NonWitnessInput.PartiallySignedNonWitnessInput -> {
                if (input.inputTx.txid != txIn.outPoint.txid) {
                    Either.Left(UpdateFailure.InvalidNonWitnessUtxo("non-witness utxo does not match unsigned tx input"))
                } else if (input.inputTx.txOut.size <= txIn.outPoint.index) {
                    Either.Left(UpdateFailure.InvalidNonWitnessUtxo("non-witness utxo index out of bounds"))
                } else {
                    signNonWitness(priv, inputIndex, input, global)
                }
            }
            is Input.FinalizedInputWithoutUtxo -> Either.Left(UpdateFailure.CannotSignInput(inputIndex, "cannot sign: input has already been finalized"))
            is Input.WitnessInput.FinalizedWitnessInput -> Either.Left(UpdateFailure.CannotSignInput(inputIndex, "cannot sign: input has already been finalized"))
            is Input.NonWitnessInput.FinalizedNonWitnessInput -> Either.Left(UpdateFailure.CannotSignInput(inputIndex, "cannot sign: input has already been finalized"))

        }
    }

    private fun signNonWitness(priv: PrivateKey, inputIndex: Int, input: Input.NonWitnessInput.PartiallySignedNonWitnessInput, global: Global): Either<UpdateFailure, Pair<Input.NonWitnessInput.PartiallySignedNonWitnessInput, ByteVector>> {
        val txIn = global.tx.txIn[inputIndex]
        val redeemScript = when (input.redeemScript) {
            null -> runCatching {
                Script.parse(input.inputTx.txOut[txIn.outPoint.index.toInt()].publicKeyScript)
            }.getOrElse {
                return Either.Left(UpdateFailure.InvalidNonWitnessUtxo("failed to parse redeem script"))
            }
            else -> {
                // If a redeem script is provided in the partially signed input, the utxo must be a p2sh for that script.
                val p2sh = Script.write(Script.pay2sh(input.redeemScript))
                if (!input.inputTx.txOut[txIn.outPoint.index.toInt()].publicKeyScript.contentEquals(p2sh)) {
                    return Either.Left(UpdateFailure.InvalidNonWitnessUtxo("redeem script does not match non-witness utxo scriptPubKey"))
                } else {
                    input.redeemScript
                }
            }
        }
        val sig = ByteVector(Transaction.signInput(global.tx, inputIndex, redeemScript, input.sighashType ?: SigHash.SIGHASH_ALL, input.amount, SigVersion.SIGVERSION_BASE, priv))
        return Either.Right(Pair(input.copy(partialSigs = input.partialSigs + (priv.publicKey() to sig)), sig))
    }

    private fun signWitness(priv: PrivateKey, inputIndex: Int, input: Input.WitnessInput.PartiallySignedWitnessInput, global: Global): Either<UpdateFailure, Pair<Input.WitnessInput.PartiallySignedWitnessInput, ByteVector>> {
        val redeemScript = when (input.redeemScript) {
            null -> {
                runCatching {
                    Script.parse(input.txOut.publicKeyScript)
                }.getOrElse {
                    return Either.Left(UpdateFailure.InvalidWitnessUtxo("failed to parse redeem script"))
                }
            }
            else -> {
                // If a redeem script is provided in the partially signed input, the utxo must be a p2sh for that script (we're using p2sh-embedded segwit).
                val p2sh = Script.write(Script.pay2sh(input.redeemScript))
                if (!input.txOut.publicKeyScript.contentEquals(p2sh)) {
                    return Either.Left(UpdateFailure.InvalidWitnessUtxo("redeem script does not match witness utxo scriptPubKey"))
                } else {
                    input.redeemScript
                }
            }
        }
        return when (input.witnessScript) {
            null -> {
                val actualScript = if (Script.isPay2wpkh(redeemScript)) Script.pay2pkh((redeemScript[1] as OP_PUSHDATA).data.toByteArray()) else redeemScript
                val sig = ByteVector(Transaction.signInput(global.tx, inputIndex, actualScript, input.sighashType ?: SigHash.SIGHASH_ALL, input.amount, SigVersion.SIGVERSION_WITNESS_V0, priv))
                Either.Right(Pair(input.copy(partialSigs = input.partialSigs + (priv.publicKey() to sig)), sig))
            }
            else -> {
                when {
                    Script.pay2wsh(input.witnessScript) == redeemScript -> {
                        val sig = ByteVector(Transaction.signInput(global.tx, inputIndex, input.witnessScript, input.sighashType ?: SigHash.SIGHASH_ALL, input.amount, SigVersion.SIGVERSION_WITNESS_V0, priv))
                        Either.Right(Pair(input.copy(partialSigs = input.partialSigs + (priv.publicKey() to sig)), sig))
                    }
                    Script.isPay2wpkh(redeemScript) -> {
                        val sig = ByteVector(Transaction.signInput(global.tx, inputIndex, Script.pay2pkh((redeemScript[1] as OP_PUSHDATA).data.toByteArray()), input.sighashType ?: SigHash.SIGHASH_ALL, input.amount, SigVersion.SIGVERSION_WITNESS_V0, priv))
                        Either.Right(Pair(input.copy(partialSigs = input.partialSigs + (priv.publicKey() to sig)), sig))
                    }
                    else -> Either.Left(UpdateFailure.InvalidWitnessUtxo("witness script does not match redeemScript or scriptPubKey"))
                }
            }
        }
    }

    /**
     * Implements the PSBT finalizer role: finalizes a given segwit input.
     * This will clear all fields from the input except the utxo, scriptSig, scriptWitness and unknown entries.
     *
     * @param outPoint input that should be finalized.
     * @param scriptWitness witness script.
     * @return a psbt with the given input finalized.
     */
    public fun finalizeWitnessInput(outPoint: OutPoint, scriptWitness: ScriptWitness): Either<UpdateFailure, Psbt> {
        val inputIndex = global.tx.txIn.indexOfFirst { it.outPoint == outPoint }
        if (inputIndex < 0) return Either.Left(UpdateFailure.InvalidInput("psbt transaction does not spend the provided outpoint"))
        return finalizeWitnessInput(inputIndex, scriptWitness)
    }

    /**
     * Implements the PSBT finalizer role: finalizes a given segwit input.
     * This will clear all fields from the input except the utxo, scriptSig, scriptWitness and unknown entries.
     *
     * @param inputIndex index of the input that should be finalized.
     * @param scriptWitness witness script.
     * @return a psbt with the given input finalized.
     */
    public fun finalizeWitnessInput(inputIndex: Int, scriptWitness: ScriptWitness): Either<UpdateFailure, Psbt> {
        if (inputIndex >= inputs.size) return Either.Left(UpdateFailure.InvalidInput("input index must exist in the input tx"))
        return when (val input = inputs[inputIndex]) {
            is Input.PartiallySignedInputWithoutUtxo -> Either.Left(UpdateFailure.CannotFinalizeInput(inputIndex, "cannot finalize: input is missing utxo details"))
            is Input.NonWitnessInput.PartiallySignedNonWitnessInput -> Either.Left(UpdateFailure.CannotFinalizeInput(inputIndex, "cannot finalize: input is a non-segwit input"))
            is Input.WitnessInput.PartiallySignedWitnessInput -> {
                val scriptSig = input.redeemScript?.let { script -> listOf(OP_PUSHDATA(Script.write(script))) } // p2sh-embedded segwit
                val finalizedInput = Input.WitnessInput.FinalizedWitnessInput(input.txOut, input.nonWitnessUtxo, scriptWitness, scriptSig, input.ripemd160, input.sha256, input.hash160, input.hash256, input.unknown)
                Either.Right(this.copy(inputs = this.inputs.updated(inputIndex, finalizedInput)))
            }
            else -> Either.Left(UpdateFailure.CannotFinalizeInput(inputIndex, ("cannot finalize: input has already been finalized")))
        }
    }

    /**
     * Implements the PSBT finalizer role: finalizes a given non-segwit input.
     * This will clear all fields from the input except the utxo, scriptSig and unknown entries.
     *
     * @param outPoint input that should be finalized.
     * @param scriptSig signature script.
     * @return a psbt with the given input finalized.
     */
    public fun finalizeNonWitnessInput(outPoint: OutPoint, scriptSig: List<ScriptElt>): Either<UpdateFailure, Psbt> {
        val inputIndex = global.tx.txIn.indexOfFirst { it.outPoint == outPoint }
        if (inputIndex < 0) return Either.Left(UpdateFailure.InvalidInput("psbt transaction does not spend the provided outpoint"))
        return finalizeNonWitnessInput(inputIndex, scriptSig)
    }

    /**
     * Implements the PSBT finalizer role: finalizes a given non-segwit input.
     * This will clear all fields from the input except the utxo, scriptSig and unknown entries.
     *
     * @param inputIndex index of the input that should be finalized.
     * @param scriptSig signature script.
     * @return a psbt with the given input finalized.
     */
    public fun finalizeNonWitnessInput(inputIndex: Int, scriptSig: List<ScriptElt>): Either<UpdateFailure, Psbt> {
        if (inputIndex >= inputs.size) return Either.Left(UpdateFailure.InvalidInput("input index must exist in the input tx"))
        return when (val input = inputs[inputIndex]) {
            is Input.PartiallySignedInputWithoutUtxo -> Either.Left(UpdateFailure.CannotFinalizeInput(inputIndex, "cannot finalize: input is missing utxo details"))
            is Input.WitnessInput.PartiallySignedWitnessInput -> Either.Left(UpdateFailure.CannotFinalizeInput(inputIndex, "cannot finalize: input is a segwit input"))
            is Input.NonWitnessInput.PartiallySignedNonWitnessInput -> {
                val finalizedInput = Input.NonWitnessInput.FinalizedNonWitnessInput(input.inputTx, input.outputIndex, scriptSig, input.ripemd160, input.sha256, input.hash160, input.hash256, input.unknown)
                Either.Right(this.copy(inputs = this.inputs.updated(inputIndex, finalizedInput)))
            }
            else -> Either.Left(UpdateFailure.CannotFinalizeInput(inputIndex, ("cannot finalize: input has already been finalized")))
        }
    }

    /**
     * Implements the PSBT extractor role: extracts a valid transaction from the psbt data.
     *
     * @return a fully signed, ready-to-broadcast transaction.
     */
    public fun extract(): Either<UpdateFailure, Transaction> {
        val (finalTxsIn, utxos) = global.tx.txIn.zip(inputs).map { (txIn, input) ->
            val finalTxIn = txIn.copy(
                witness = input.scriptWitness ?: ScriptWitness.empty,
                signatureScript = input.scriptSig?.let { ByteVector(Script.write(it)) } ?: ByteVector.empty
            )
            val utxo = when (input) {
                is Input.NonWitnessInput.FinalizedNonWitnessInput -> {
                    if (input.inputTx.txid != txIn.outPoint.txid) return Either.Left(UpdateFailure.CannotExtractTx("non-witness utxo does not match unsigned tx input"))
                    if (input.inputTx.txOut.size <= txIn.outPoint.index) return Either.Left(UpdateFailure.CannotExtractTx("non-witness utxo index out of bounds"))
                    input.inputTx.txOut[txIn.outPoint.index.toInt()]
                }
                is Input.WitnessInput.FinalizedWitnessInput -> input.txOut
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

    /**
     * Compute the fees paid by the PSBT.
     * Note that if some inputs have not been updated yet, the fee cannot be computed.
     */
    public fun computeFees(): Satoshi? {
        val inputAmounts = inputs.map { input ->
            when (input) {
                is Input.WitnessInput -> input.amount
                is Input.NonWitnessInput -> input.amount
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

    public fun getInput(outPoint: OutPoint): Input? {
        val inputIndex = global.tx.txIn.indexOfFirst { it.outPoint == outPoint }
        return if (inputIndex >= 0) inputs[inputIndex] else null
    }

    public fun getInput(inputIndex: Int): Input? {
        return if (0 <= inputIndex && inputIndex < inputs.size) inputs[inputIndex] else null
    }

    public companion object {

        /** Only version 0 is supported for now. */
        public const val Version: Long = 0


        /**
         * Implements the PSBT combiner role: combines multiple psbts for the same unsigned transaction.
         *
         * @param psbts partially signed bitcoin transactions to combine.
         * @return a psbt that contains data from all the input psbts.
         */
        @JvmStatic
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
                        global.tx.txIn.indices.map { i -> combineInput(global.tx.txIn[i], psbts.map { it.inputs[i] }) },
                        global.tx.txOut.indices.map { i -> combineOutput(psbts.map { it.outputs[i] }) }
                    )
                    Either.Right(combined)
                }
            }
        }

        private fun combineUnknown(unknowns: List<List<DataEntry>>): List<DataEntry> = unknowns.flatten().associateBy { it.key }.values.toList()

        private fun combineExtendedPublicKeys(keys: List<List<ExtendedPublicKeyWithMaster>>): List<ExtendedPublicKeyWithMaster> = keys.flatten().associateBy { it.extendedPublicKey }.values.toList()

        private fun combineInput(txIn: TxIn, inputs: List<Input>): Input = createInput(
            txIn,
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

        private fun combineOutput(outputs: List<Output>): Output = createOutput(
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
        @JvmStatic
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

        @JvmStatic
        public fun write(psbt: Psbt): ByteVector {
            val output = ByteArrayOutput()
            write(psbt, output)
            return ByteVector(output.toByteArray())
        }

        @JvmStatic
        public fun write(psbt: Psbt, out: fr.acinq.bitcoin.io.Output) {
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

        private fun writeDataEntry(entry: DataEntry, output: fr.acinq.bitcoin.io.Output) {
            BtcSerializer.writeVarint(entry.key.size(), output)
            output.write(entry.key.bytes)
            BtcSerializer.writeVarint(entry.value.size(), output)
            output.write(entry.value.bytes)
        }

        @JvmStatic
        public fun read(input: ByteVector): Either<ParseFailure, Psbt> = read(ByteArrayInput(input.toByteArray()))

        @JvmStatic
        public fun read(input: ByteArray): Either<ParseFailure, Psbt> = read(ByteArrayInput(input))

        @JvmStatic
        public fun read(input: fr.acinq.bitcoin.io.Input): Either<ParseFailure, Psbt> {
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
                createInput(
                    txIn,
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
                createOutput(redeemScript, witnessScript, derivationPaths, unknown)
            }

            return if (input.availableBytes != 0) {
                Either.Left(ParseFailure.InvalidContent)
            } else {
                Either.Right(Psbt(global, inputs, outputs))
            }
        }

        private fun createInput(
            txIn: TxIn,
            nonWitnessUtxo: Transaction?,
            witnessUtxo: TxOut?,
            sighashType: Int?,
            partialSigs: Map<PublicKey, ByteVector>,
            derivationPaths: Map<PublicKey, KeyPathWithMaster>,
            redeemScript: List<ScriptElt>?,
            witnessScript: List<ScriptElt>?,
            scriptSig: List<ScriptElt>?,
            scriptWitness: ScriptWitness?,
            ripemd160: Set<ByteVector>,
            sha256: Set<ByteVector>,
            hash160: Set<ByteVector>,
            hash256: Set<ByteVector>,
            unknown: List<DataEntry>
        ): Input {
            val emptied = redeemScript == null && witnessScript == null && partialSigs.isEmpty() && derivationPaths.isEmpty() && sighashType == null
            return when {
                // @formatter:off
                // If the input is finalized, it must have been emptied otherwise it's invalid.
                witnessUtxo != null && scriptWitness != null && emptied -> Input.WitnessInput.FinalizedWitnessInput(witnessUtxo, nonWitnessUtxo, scriptWitness, scriptSig, ripemd160, sha256, hash160, hash256, unknown)
                nonWitnessUtxo != null && scriptSig != null && emptied -> Input.NonWitnessInput.FinalizedNonWitnessInput(nonWitnessUtxo, txIn.outPoint.index.toInt(), scriptSig, ripemd160, sha256, hash160, hash256, unknown)
                (scriptSig != null || scriptWitness != null) && emptied -> Input.FinalizedInputWithoutUtxo(scriptWitness, scriptSig, ripemd160, sha256, hash160, hash256, unknown)
                witnessUtxo != null -> Input.WitnessInput.PartiallySignedWitnessInput(witnessUtxo, nonWitnessUtxo, sighashType, partialSigs, derivationPaths, redeemScript, witnessScript, ripemd160, sha256, hash160, hash256, unknown)
                nonWitnessUtxo != null -> Input.NonWitnessInput.PartiallySignedNonWitnessInput(nonWitnessUtxo, txIn.outPoint.index.toInt(), sighashType, partialSigs, derivationPaths, redeemScript, ripemd160, sha256, hash160, hash256, unknown)
                else -> Input.PartiallySignedInputWithoutUtxo(sighashType, derivationPaths, ripemd160, sha256, hash160, hash256, unknown)
                // @formatter:on
            }
        }

        private fun createOutput(
            redeemScript: List<ScriptElt>?,
            witnessScript: List<ScriptElt>?,
            derivationPaths: Map<PublicKey, KeyPathWithMaster>,
            unknown: List<DataEntry>
        ): Output = when {
            witnessScript != null -> Output.WitnessOutput(witnessScript, redeemScript, derivationPaths, unknown)
            redeemScript != null -> Output.NonWitnessOutput(redeemScript, derivationPaths, unknown)
            else -> Output.UnspecifiedOutput(derivationPaths, unknown)
        }

        private sealed class ReadEntryFailure {
            object DuplicateKeys : ReadEntryFailure()
            object InvalidData : ReadEntryFailure()
            object EndOfDataMap : ReadEntryFailure()
        }

        private fun readDataMap(input: fr.acinq.bitcoin.io.Input, entries: List<DataEntry> = listOf()): Either<ReadEntryFailure, List<DataEntry>> {
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

        private fun readDataEntry(input: fr.acinq.bitcoin.io.Input): Either<ReadEntryFailure, DataEntry> {
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

/** A PSBT input. A valid PSBT must contain one such input per input of the [[Global.tx]]. */
public sealed class Input {
    // @formatter:off
    /** Non-witness utxo, used when spending non-segwit outputs (may also be included when spending segwit outputs). */
    public abstract val nonWitnessUtxo: Transaction?
    /** Witness utxo, used when spending segwit outputs. */
    public abstract val witnessUtxo: TxOut?
    /** Sighash type to be used when producing signatures for this output. */
    public abstract val sighashType: Int?
    /** Signatures as would be pushed to the stack from a scriptSig or witness. */
    public abstract val partialSigs: Map<PublicKey, ByteVector>
    /** Derivation paths used for the signatures. */
    public abstract val derivationPaths: Map<PublicKey, KeyPathWithMaster>
    /** Redeem script for this input (when using p2sh). */
    public abstract val redeemScript: List<ScriptElt>?
    /** Witness script for this input (when using p2wsh). */
    public abstract val witnessScript: List<ScriptElt>?
    /** Fully constructed scriptSig with signatures and any other scripts necessary for the input to pass validation. */
    public abstract val scriptSig: List<ScriptElt>?
    /** Fully constructed scriptWitness with signatures and any other scripts necessary for the input to pass validation. */
    public abstract val scriptWitness: ScriptWitness?
    /** RipeMD160 preimages (e.g. for miniscript hash challenges). */
    public abstract val ripemd160: Set<ByteVector>
    /** Sha256 preimages (e.g. for miniscript hash challenges). */
    public abstract val sha256: Set<ByteVector>
    /** Hash160 preimages (e.g. for miniscript hash challenges). */
    public abstract val hash160: Set<ByteVector>
    /** Hash256 preimages (e.g. for miniscript hash challenges). */
    public abstract val hash256: Set<ByteVector>
    /** (optional) Unknown global entries. */
    public abstract val unknown: List<DataEntry>
    // @formatter:on

    /**
     * A partially signed input without details about the utxo.
     * More signatures may need to be added before it can be finalized.
     */
    public data class PartiallySignedInputWithoutUtxo(
        override val sighashType: Int?,
        override val derivationPaths: Map<PublicKey, KeyPathWithMaster>,
        override val ripemd160: Set<ByteVector>,
        override val sha256: Set<ByteVector>,
        override val hash160: Set<ByteVector>,
        override val hash256: Set<ByteVector>,
        override val unknown: List<DataEntry>
    ) : Input() {
        override val nonWitnessUtxo: Transaction? = null
        override val witnessUtxo: TxOut? = null
        override val redeemScript: List<ScriptElt>? = null
        override val witnessScript: List<ScriptElt>? = null
        override val partialSigs: Map<PublicKey, ByteVector> = mapOf()
        override val scriptSig: List<ScriptElt>? = null
        override val scriptWitness: ScriptWitness? = null
    }

    /**
     * A fully signed input without details about the utxo.
     * Input finalizers should keep the utxo to allow transaction extractors to verify the final network serialized
     * transaction, but it's not mandatory, so we may not have it available when parsing psbt inputs.
     */
    public data class FinalizedInputWithoutUtxo(
        override val scriptWitness: ScriptWitness?,
        override val scriptSig: List<ScriptElt>?,
        override val ripemd160: Set<ByteVector>,
        override val sha256: Set<ByteVector>,
        override val hash160: Set<ByteVector>,
        override val hash256: Set<ByteVector>,
        override val unknown: List<DataEntry>
    ) : Input() {
        override val nonWitnessUtxo: Transaction? = null
        override val witnessUtxo: TxOut? = null
        override val sighashType: Int? = null
        override val partialSigs: Map<PublicKey, ByteVector> = mapOf()
        override val derivationPaths: Map<PublicKey, KeyPathWithMaster> = mapOf()
        override val redeemScript: List<ScriptElt>? = null
        override val witnessScript: List<ScriptElt>? = null
    }

    /** An input spending a segwit output. */
    public sealed class WitnessInput : Input() {
        public abstract val txOut: TxOut
        public val amount: Satoshi by lazy { txOut.amount }
        override val witnessUtxo: TxOut? by lazy { txOut }

        /** A partially signed segwit input. More signatures may need to be added before it can be finalized. */
        public data class PartiallySignedWitnessInput(
            override val txOut: TxOut,
            override val nonWitnessUtxo: Transaction?,
            override val sighashType: Int?,
            override val partialSigs: Map<PublicKey, ByteVector>,
            override val derivationPaths: Map<PublicKey, KeyPathWithMaster>,
            override val redeemScript: List<ScriptElt>?,
            override val witnessScript: List<ScriptElt>?,
            override val ripemd160: Set<ByteVector>,
            override val sha256: Set<ByteVector>,
            override val hash160: Set<ByteVector>,
            override val hash256: Set<ByteVector>,
            override val unknown: List<DataEntry>
        ) : WitnessInput() {
            override val scriptSig: List<ScriptElt>? = null
            override val scriptWitness: ScriptWitness? = null
        }

        /** A fully signed segwit input. */
        public data class FinalizedWitnessInput(
            override val txOut: TxOut,
            override val nonWitnessUtxo: Transaction?,
            override val scriptWitness: ScriptWitness,
            override val scriptSig: List<ScriptElt>?,
            override val ripemd160: Set<ByteVector>,
            override val sha256: Set<ByteVector>,
            override val hash160: Set<ByteVector>,
            override val hash256: Set<ByteVector>,
            override val unknown: List<DataEntry>
        ) : WitnessInput() {
            override val sighashType: Int? = null
            override val partialSigs: Map<PublicKey, ByteVector> = mapOf()
            override val derivationPaths: Map<PublicKey, KeyPathWithMaster> = mapOf()
            override val redeemScript: List<ScriptElt>? = null
            override val witnessScript: List<ScriptElt>? = null
        }
    }

    /** An input spending a non-segwit output. */
    public sealed class NonWitnessInput : Input() {
        public abstract val inputTx: Transaction
        public abstract val outputIndex: Int
        public val amount: Satoshi by lazy { inputTx.txOut[outputIndex].amount }
        override val nonWitnessUtxo: Transaction? by lazy { inputTx }

        // The following fields should only be present for inputs which spend segwit outputs (including P2SH embedded ones).
        override val witnessUtxo: TxOut? = null
        override val witnessScript: List<ScriptElt>? = null

        /** A partially signed non-segwit input. More signatures may need to be added before it can be finalized. */
        public data class PartiallySignedNonWitnessInput(
            override val inputTx: Transaction,
            override val outputIndex: Int,
            override val sighashType: Int?,
            override val partialSigs: Map<PublicKey, ByteVector>,
            override val derivationPaths: Map<PublicKey, KeyPathWithMaster>,
            override val redeemScript: List<ScriptElt>?,
            override val ripemd160: Set<ByteVector>,
            override val sha256: Set<ByteVector>,
            override val hash160: Set<ByteVector>,
            override val hash256: Set<ByteVector>,
            override val unknown: List<DataEntry>
        ) : NonWitnessInput() {
            override val scriptSig: List<ScriptElt>? = null
            override val scriptWitness: ScriptWitness? = null
        }

        /** A fully signed non-segwit input. */
        public data class FinalizedNonWitnessInput(
            override val inputTx: Transaction,
            override val outputIndex: Int,
            override val scriptSig: List<ScriptElt>,
            override val ripemd160: Set<ByteVector>,
            override val sha256: Set<ByteVector>,
            override val hash160: Set<ByteVector>,
            override val hash256: Set<ByteVector>,
            override val unknown: List<DataEntry>
        ) : NonWitnessInput() {
            override val sighashType: Int? = null
            override val partialSigs: Map<PublicKey, ByteVector> = mapOf()
            override val derivationPaths: Map<PublicKey, KeyPathWithMaster> = mapOf()
            override val redeemScript: List<ScriptElt>? = null
            override val witnessScript: List<ScriptElt>? = null
            override val scriptWitness: ScriptWitness? = null
        }
    }
}

/** A PSBT output. A valid PSBT must contain one such output per output of the [[Global.tx]]. */
public sealed class Output {
    // @formatter:off
    /** Redeem script for this output (when using p2sh). */
    public abstract val redeemScript: List<ScriptElt>?
    /** Witness script for this output (when using p2wsh). */
    public abstract val witnessScript: List<ScriptElt>?
    /** Derivation paths used to produce the public keys associated to this output. */
    public abstract val derivationPaths: Map<PublicKey, KeyPathWithMaster>
    /** (optional) Unknown global entries. */
    public abstract val unknown: List<DataEntry>
    // @formatter:on

    /** A non-segwit output. */
    public data class NonWitnessOutput(
        override val redeemScript: List<ScriptElt>?,
        override val derivationPaths: Map<PublicKey, KeyPathWithMaster>,
        override val unknown: List<DataEntry>
    ) : Output() {
        override val witnessScript: List<ScriptElt>? = null
    }

    /** A segwit output. */
    public data class WitnessOutput(
        override val witnessScript: List<ScriptElt>?,
        override val redeemScript: List<ScriptElt>?,
        override val derivationPaths: Map<PublicKey, KeyPathWithMaster>,
        override val unknown: List<DataEntry>
    ) : Output()

    /** An output for which usage of segwit is currently unknown. */
    public data class UnspecifiedOutput(
        override val derivationPaths: Map<PublicKey, KeyPathWithMaster>,
        override val unknown: List<DataEntry>
    ) : Output() {
        override val redeemScript: List<ScriptElt>? = null
        override val witnessScript: List<ScriptElt>? = null
    }
}

public sealed class UpdateFailure {
    public data class InvalidInput(val reason: String) : UpdateFailure()
    public data class InvalidNonWitnessUtxo(val reason: String) : UpdateFailure()
    public data class InvalidWitnessUtxo(val reason: String) : UpdateFailure()
    public data class CannotCombine(val reason: String) : UpdateFailure()
    public data class CannotJoin(val reason: String) : UpdateFailure()
    public data class CannotUpdateInput(val index: Int, val reason: String) : UpdateFailure()
    public data class CannotUpdateOutput(val index: Int, val reason: String) : UpdateFailure()
    public data class CannotSignInput(val index: Int, val reason: String) : UpdateFailure()
    public data class CannotFinalizeInput(val index: Int, val reason: String) : UpdateFailure()
    public data class CannotExtractTx(val reason: String) : UpdateFailure()
}

public data class SignPsbtResult(val psbt: Psbt, val sig: ByteVector)

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

