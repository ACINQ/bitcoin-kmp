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

/**
 * A partially signed bitcoin transaction: see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki.
 *
 * @param global global psbt data containing the transaction to be signed.
 * @param inputs signing data for each input of the transaction to be signed (order matches the unsigned tx).
 * @param outputs signing data for each output of the transaction to be signed (order matches the unsigned tx).
 */
@OptIn(ExperimentalUnsignedTypes::class)
public data class Psbt(val global: Global, val inputs: List<PartiallySignedInput>, val outputs: List<PartiallySignedOutput>) {

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
            val ripemd160: List<ByteVector>,
            val sha256: List<ByteVector>,
            val hash160: List<ByteVector>,
            val hash256: List<ByteVector>,
            val unknown: List<DataEntry>
        ) {
            public companion object {
                public val empty: PartiallySignedInput = PartiallySignedInput(null, null, null, mapOf(), mapOf(), null, null, null, null, listOf(), listOf(), listOf(), listOf(), listOf())
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

        public sealed class ParsePsbtResult {
            public data class Success(val psbt: Psbt) : ParsePsbtResult()
            public sealed class Failure : ParsePsbtResult() {
                public object InvalidMagicBytes : ParsePsbtResult()
                public object InvalidSeparator : ParsePsbtResult()
                public object DuplicateKeys : ParsePsbtResult()
                public data class InvalidPsbtVersion(val reason: String) : ParsePsbtResult()
                public data class UnsupportedPsbtVersion(val version: Long) : ParsePsbtResult()
                public data class InvalidGlobalTx(val reason: String) : ParsePsbtResult()
                public object GlobalTxMissing : ParsePsbtResult()
                public data class InvalidExtendedPublicKey(val reason: String) : ParsePsbtResult()
                public data class InvalidTxInput(val reason: String) : ParsePsbtResult()
                public data class InvalidTxOutput(val reason: String) : ParsePsbtResult()
                public object InvalidContent : ParsePsbtResult()
            }
        }

        public fun read(input: ByteVector): ParsePsbtResult = read(ByteArrayInput(input.toByteArray()))
        public fun read(input: ByteArray): ParsePsbtResult = read(ByteArrayInput(input))
        public fun read(input: Input): ParsePsbtResult {
            /********** Magic header **********/
            if (input.read() != 0x70 || input.read() != 0x73 || input.read() != 0x62 || input.read() != 0x74) {
                return ParsePsbtResult.Failure.InvalidMagicBytes
            }
            if (input.read() != 0xff) {
                return ParsePsbtResult.Failure.InvalidSeparator
            }

            /********** Global types **********/
            val global = run {
                val globalMap = when (val result = readDataMap(input)) {
                    ReadDataMapResult.DuplicateKeys -> return ParsePsbtResult.Failure.DuplicateKeys
                    ReadDataMapResult.InvalidData -> return ParsePsbtResult.Failure.InvalidContent
                    is ReadDataMapResult.Success -> result.entries
                }
                val keyTypes = setOf(0x00.toByte(), 0x01.toByte(), 0xfb.toByte())
                val (known, unknown) = globalMap.partition { keyTypes.contains(it.key[0]) }
                val version = known.find { it.key[0] == 0xfb.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidPsbtVersion("version key must contain exactly 1 byte")
                        it.value.size() != 4 -> return ParsePsbtResult.Failure.InvalidPsbtVersion("version must contain exactly 4 bytes")
                        else -> {
                            val v = Pack.int32LE(it.value.bytes).toUInt().toLong()
                            when {
                                v > Version -> return ParsePsbtResult.Failure.UnsupportedPsbtVersion(v)
                                else -> v
                            }
                        }
                    }
                } ?: 0L
                val tx = known.find { it.key[0] == 0x00.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidGlobalTx("global tx key must contain exactly 1 byte")
                        else -> {
                            val tx = try {
                                Transaction.read(it.value.bytes, Protocol.PROTOCOL_VERSION or Transaction.SERIALIZE_TRANSACTION_NO_WITNESS)
                            } catch (e: Exception) {
                                return ParsePsbtResult.Failure.InvalidGlobalTx(e.message ?: "failed to parse transaction")
                            }
                            when {
                                tx.txIn.any { input -> input.hasWitness || !input.signatureScript.isEmpty() } -> return ParsePsbtResult.Failure.InvalidGlobalTx("global tx inputs must have empty scriptSigs and witness")
                                else -> tx
                            }
                        }
                    }
                } ?: return ParsePsbtResult.Failure.GlobalTxMissing
                val xpubs = known.filter { it.key[0] == 0x01.toByte() }.map {
                    when {
                        it.key.size() != 79 -> return ParsePsbtResult.Failure.InvalidExtendedPublicKey("<xpub> must contain 78 bytes")
                        else -> {
                            val xpub = ByteArrayInput(it.key.drop(1).toByteArray())
                            val prefix = Pack.int32BE(xpub).toUInt().toLong()
                            val depth = xpub.read()
                            val parent = Pack.int32BE(xpub).toUInt().toLong()
                            val childNumber = Pack.int32BE(xpub).toUInt().toLong()
                            val chainCode = ByteVector32(xpub.readNBytes(32))
                            val publicKey = ByteVector(xpub.readNBytes(33))
                            when {
                                it.value.size() != 4 * (depth + 1) -> return ParsePsbtResult.Failure.InvalidExtendedPublicKey("<xpub> must contain the master key fingerprint and derivation path")
                                else -> {
                                    val masterKeyFingerprint = Pack.int32BE(it.value.take(4).toByteArray()).toUInt().toLong()
                                    val derivationPath = KeyPath((0 until depth).map { i -> Pack.int32LE(it.value.slice(4 * (i + 1), 4 * (i + 2)).toByteArray()).toUInt().toLong() })
                                    when {
                                        derivationPath.lastChildNumber != childNumber -> return ParsePsbtResult.Failure.InvalidExtendedPublicKey("<xpub> last child number mismatch")
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
                val entries = when (val result = readDataMap(input)) {
                    ReadDataMapResult.DuplicateKeys -> return ParsePsbtResult.Failure.DuplicateKeys
                    ReadDataMapResult.InvalidData -> return ParsePsbtResult.Failure.InvalidContent
                    is ReadDataMapResult.Success -> result.entries
                }
                val (known, unknown) = entries.partition { keyTypes.contains(it.key[0]) }
                val nonWitnessUtxo = known.find { it.key[0] == 0x00.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxInput("non-witness utxo key must contain exactly 1 byte")
                        else -> {
                            val inputTx = try {
                                Transaction.read(it.value.bytes)
                            } catch (e: Exception) {
                                return ParsePsbtResult.Failure.InvalidTxInput(e.message ?: "failed to parse transaction")
                            }
                            when {
                                inputTx.txid != txIn.outPoint.txid || txIn.outPoint.index >= inputTx.txOut.size -> return ParsePsbtResult.Failure.InvalidTxInput("non-witness utxo does not match psbt outpoint")
                                else -> inputTx
                            }
                        }
                    }
                }
                val witnessUtxo = known.find { it.key[0] == 0x01.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxInput("witness utxo key must contain exactly 1 byte")
                        else -> {
                            try {
                                TxOut.read(it.value.bytes)
                            } catch (e: Exception) {
                                return ParsePsbtResult.Failure.InvalidTxInput(e.message ?: "failed to parse transaction output")
                            }
                        }
                    }
                }
                val partialSigs = known.filter { it.key[0] == 0x02.toByte() }.map {
                    when {
                        it.key.size() != 34 -> return ParsePsbtResult.Failure.InvalidTxInput("public key must contain exactly 33 bytes")
                        else -> PublicKey(it.key.drop(1)) to it.value
                    }
                }.toMap()
                val sighashType = known.find { it.key[0] == 0x03.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxInput("sighash type key must contain exactly 1 byte")
                        it.value.size() != 4 -> return ParsePsbtResult.Failure.InvalidTxInput("sighash type must contain exactly 4 bytes")
                        else -> Pack.int32LE(it.value.bytes)
                    }
                }
                val redeemScript = known.find { it.key[0] == 0x04.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxInput("redeem script key must contain exactly 1 byte")
                        else -> try {
                            Script.parse(it.value)
                        } catch (e: Exception) {
                            return ParsePsbtResult.Failure.InvalidTxInput(e.message ?: "failed to parse redeem script")
                        }
                    }
                }
                val witnessScript = known.find { it.key[0] == 0x05.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxInput("witness script key must contain exactly 1 byte")
                        else -> try {
                            Script.parse(it.value)
                        } catch (e: Exception) {
                            return ParsePsbtResult.Failure.InvalidTxInput(e.message ?: "failed to parse witness script")
                        }
                    }
                }
                val derivationPaths = known.filter { it.key[0] == 0x06.toByte() }.map {
                    when {
                        it.key.size() != 34 -> return ParsePsbtResult.Failure.InvalidTxInput("bip32 derivation public key must contain exactly 33 bytes")
                        it.value.size() < 4 || it.value.size() % 4 != 0 -> return ParsePsbtResult.Failure.InvalidTxInput("bip32 derivation must contain master key fingerprint and child indexes")
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
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxInput("script sig key must contain exactly 1 byte")
                        else -> try {
                            Script.parse(it.value)
                        } catch (e: Exception) {
                            return ParsePsbtResult.Failure.InvalidTxInput(e.message ?: "failed to parse script sig")
                        }
                    }
                }
                val scriptWitness = known.find { it.key[0] == 0x08.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxInput("script witness key must contain exactly 1 byte")
                        else -> try {
                            ScriptWitness.read(it.value.bytes)
                        } catch (e: Exception) {
                            return ParsePsbtResult.Failure.InvalidTxInput(e.message ?: "failed to parse script witness")
                        }
                    }
                }
                val ripemd160Preimages = known.filter { it.key[0] == 0x0a.toByte() }.map {
                    when {
                        it.key.size() != 21 -> return ParsePsbtResult.Failure.InvalidTxInput("ripemd160 hash must contain exactly 20 bytes")
                        !it.key.drop(1).contentEquals(Crypto.ripemd160(it.value)) -> return ParsePsbtResult.Failure.InvalidTxInput("invalid ripemd160 preimage")
                        else -> it.value
                    }
                }
                val sha256Preimages = known.filter { it.key[0] == 0x0b.toByte() }.map {
                    when {
                        it.key.size() != 33 -> return ParsePsbtResult.Failure.InvalidTxInput("sha256 hash must contain exactly 32 bytes")
                        !it.key.drop(1).contentEquals(Crypto.sha256(it.value)) -> return ParsePsbtResult.Failure.InvalidTxInput("invalid sha256 preimage")
                        else -> it.value
                    }
                }
                val hash160Preimages = known.filter { it.key[0] == 0x0c.toByte() }.map {
                    when {
                        it.key.size() != 21 -> return ParsePsbtResult.Failure.InvalidTxInput("hash160 hash must contain exactly 20 bytes")
                        !it.key.drop(1).contentEquals(Crypto.hash160(it.value)) -> return ParsePsbtResult.Failure.InvalidTxInput("invalid hash160 preimage")
                        else -> it.value
                    }
                }
                val hash256Preimages = known.filter { it.key[0] == 0x0d.toByte() }.map {
                    when {
                        it.key.size() != 33 -> return ParsePsbtResult.Failure.InvalidTxInput("hash256 hash must contain exactly 32 bytes")
                        !it.key.drop(1).contentEquals(Crypto.hash256(it.value)) -> return ParsePsbtResult.Failure.InvalidTxInput("invalid hash256 preimage")
                        else -> it.value
                    }
                }
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
                val entries = when (val result = readDataMap(input)) {
                    ReadDataMapResult.DuplicateKeys -> return ParsePsbtResult.Failure.DuplicateKeys
                    ReadDataMapResult.InvalidData -> return ParsePsbtResult.Failure.InvalidContent
                    is ReadDataMapResult.Success -> result.entries
                }
                val (known, unknown) = entries.partition { keyTypes.contains(it.key[0]) }
                val redeemScript = known.find { it.key[0] == 0x00.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxOutput("redeem script key must contain exactly 1 byte")
                        else -> try {
                            Script.parse(it.value)
                        } catch (e: Exception) {
                            return ParsePsbtResult.Failure.InvalidTxOutput(e.message ?: "failed to parse redeem script")
                        }
                    }
                }
                val witnessScript = known.find { it.key[0] == 0x01.toByte() }?.let {
                    when {
                        it.key.size() != 1 -> return ParsePsbtResult.Failure.InvalidTxOutput("witness script key must contain exactly 1 byte")
                        else -> try {
                            Script.parse(it.value)
                        } catch (e: Exception) {
                            return ParsePsbtResult.Failure.InvalidTxOutput(e.message ?: "failed to parse witness script")
                        }
                    }
                }
                val derivationPaths = known.filter { it.key[0] == 0x02.toByte() }.map {
                    when {
                        it.key.size() != 34 -> return ParsePsbtResult.Failure.InvalidTxOutput("bip32 derivation public key must contain exactly 33 bytes")
                        it.value.size() < 4 || it.value.size() % 4 != 0 -> return ParsePsbtResult.Failure.InvalidTxOutput("bip32 derivation must contain master key fingerprint and child indexes")
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
                ParsePsbtResult.Failure.InvalidContent
            } else {
                ParsePsbtResult.Success(Psbt(global, inputs, outputs))
            }
        }

        private sealed class ReadDataMapResult {
            data class Success(val entries: List<DataEntry>) : ReadDataMapResult()
            object DuplicateKeys : ReadDataMapResult()
            object InvalidData : ReadDataMapResult()
        }

        private fun readDataMap(input: Input, entries: List<DataEntry> = listOf()): ReadDataMapResult {
            return when (val result = readDataEntry(input)) {
                is ReadDataEntryResult.Success -> readDataMap(input, entries + result.entry)
                ReadDataEntryResult.EndOfDataMap -> {
                    if (entries.map { it.key }.toSet().size != entries.size) {
                        ReadDataMapResult.DuplicateKeys
                    } else {
                        ReadDataMapResult.Success(entries)
                    }
                }
                ReadDataEntryResult.InvalidData -> ReadDataMapResult.InvalidData
            }
        }

        private sealed class ReadDataEntryResult {
            data class Success(val entry: DataEntry) : ReadDataEntryResult()
            object EndOfDataMap : ReadDataEntryResult()
            object InvalidData : ReadDataEntryResult()
        }

        private fun readDataEntry(input: Input): ReadDataEntryResult {
            if (input.availableBytes == 0) return ReadDataEntryResult.InvalidData
            val keyLength = BtcSerializer.varint(input).toInt()
            if (keyLength == 0) return ReadDataEntryResult.EndOfDataMap
            val key = input.readNBytesStrict(keyLength) ?: return ReadDataEntryResult.InvalidData

            if (input.availableBytes == 0) return ReadDataEntryResult.InvalidData
            val valueLength = BtcSerializer.varint(input).toInt()
            val value = input.readNBytesStrict(valueLength) ?: return ReadDataEntryResult.InvalidData

            return ReadDataEntryResult.Success(DataEntry(ByteVector(key), ByteVector(value)))
        }
    }

}