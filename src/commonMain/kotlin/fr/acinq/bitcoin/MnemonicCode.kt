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

import fr.acinq.bitcoin.crypto.Pbkdf2
import kotlin.jvm.JvmStatic

public object MnemonicCode {

    private fun toBinary(x: Byte): List<Boolean> {
        tailrec fun loop(x: Int, acc: List<Boolean> = listOf()): List<Boolean> =
            if (x == 0) acc else loop(x / 2, listOf((x % 2) != 0) + acc)

        val digits = loop(x.toInt() and 0xff)
        val zeroes = List(8 - digits.size) { false }
        return zeroes + digits
    }

    private fun toBinary(x: ByteArray): List<Boolean> = x.map(MnemonicCode::toBinary).flatten()

    private fun fromBinary(bin: List<Boolean>): Int = bin.fold(0) { acc, flag -> if (flag) 2 * acc + 1 else 2 * acc }

    private tailrec fun group(items: List<Boolean>, size: Int, acc: List<List<Boolean>> = emptyList()): List<List<Boolean>> {
        return when {
            items.isEmpty() -> acc
            items.size < size -> acc + listOf(items)
            else -> group(items.drop(size), size, acc + listOf(items.take(size)))
        }
    }

    /**
     * @param mnemonics list of mnemonic words
     * @param wordlist optional dictionary of 2048 mnemonic words, default to the English mnemonic words if not specified
     * @throws RuntimeException if the mnemonic words are not valid
     */
    @JvmStatic
    public fun validate(mnemonics: List<String>, wordlist: List<String> = MnemonicLanguage.English.wordlist()) {
        require(wordlist.size == 2048) { "invalid word list (size should be 2048)" }
        require(mnemonics.isNotEmpty()) { "mnemonic code cannot be empty" }
        require(mnemonics.size % 3 == 0) { "invalid mnemonic word count " + mnemonics.size + ", it must be a multiple of 3" }
        val wordMap = wordlist.mapIndexed { index, s -> s to index }.toMap()
        mnemonics.forEach { word -> require(wordMap.contains(word)) { "invalid mnemonic word $word" } }
        val indexes = mnemonics.map { word -> wordMap.getValue(word) }

        tailrec fun toBits(index: Int, acc: List<Boolean> = listOf()): List<Boolean> =
            if (acc.size == 11) acc else toBits(index / 2, listOf(index % 2 != 0) + acc)

        val bits = indexes.map { toBits(it) }.flatten()
        val bitlength = (bits.size * 32) / 33
        val databits = bits.subList(0, bitlength)
        val checksumbits = bits.subList(bitlength, bits.size)
        val data = group(databits, 8).map { fromBinary(it) }.map { it.toByte() }.toByteArray()
        val check = toBinary(Crypto.sha256(data)).take(data.size / 4)
        require(check == checksumbits) { "invalid checksum" }
    }

    @JvmStatic
    public fun validate(mnemonics: String): Unit = validate(mnemonics.split(" "))

    /**
     * BIP39 entropy encoding
     *
     * @param entropy  input entropy
     * @param wordlist word list (must be 2048 words long)
     * @return a list of mnemonic words that encodes the input entropy
     */
    @JvmStatic
    public fun toMnemonics(entropy: ByteArray, wordlist: List<String>): List<String> {
        require(wordlist.size == 2048) { "invalid word list (size should be 2048)" }
        val digits = toBinary(entropy) + toBinary(Crypto.sha256(entropy)).take(entropy.size / 4)

        return group(digits, 11).map(MnemonicCode::fromBinary).map { wordlist[it] }
    }

    @JvmStatic
    public fun toMnemonics(entropy: ByteArray, language: MnemonicLanguage): List<String> = toMnemonics(entropy, language.wordlist())

    @JvmStatic
    public fun toMnemonics(entropy: ByteArray): List<String> = toMnemonics(entropy, MnemonicLanguage.English)

    /**
     * BIP39 seed derivation
     *
     * @param mnemonics  mnemonic words
     * @param passphrase passphrase
     * @return a seed derived from the mnemonic words and passphrase
     */
    @JvmStatic
    public fun toSeed(mnemonics: List<String>, passphrase: String): ByteArray {
        val password = mnemonics.joinToString(" ").encodeToByteArray()
        val salt = ("mnemonic$passphrase").encodeToByteArray()
        return Pbkdf2.withHmacSha512(password, salt, 2048, 64)
    }

    @JvmStatic
    public fun toSeed(mnemonics: String, passphrase: String): ByteArray = toSeed(mnemonics.split(" "), passphrase)
}