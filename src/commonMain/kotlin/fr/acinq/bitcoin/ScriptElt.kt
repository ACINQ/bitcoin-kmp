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

import kotlin.jvm.JvmField
import kotlin.jvm.JvmStatic

sealed class ScriptElt {
    fun isPush(size: Int): Boolean = ScriptElt.isPush(this, size)

    fun isPush(): Boolean = ScriptElt.isPush(this)

    companion object {
        @JvmStatic
        fun isPush(op: ScriptElt): Boolean {
            return when {
                op is OP_PUSHDATA -> true
                else -> false
            }
        }

        @JvmStatic
        fun isPush(op: ScriptElt, size: Int): Boolean {
            return when {
                op is OP_PUSHDATA && op.data.size() == size -> true
                else -> false
            }
        }
    }
}

// @formatter:off
object OP_0 : ScriptElt()
object OP_PUSHDATA1 : ScriptElt()
object OP_PUSHDATA2 : ScriptElt()
object OP_PUSHDATA4 : ScriptElt()
object OP_1NEGATE : ScriptElt()
object OP_RESERVED : ScriptElt()
object OP_1 : ScriptElt()
object OP_2 : ScriptElt()
object OP_3 : ScriptElt()
object OP_4 : ScriptElt()
object OP_5 : ScriptElt()
object OP_6 : ScriptElt()
object OP_7 : ScriptElt()
object OP_8 : ScriptElt()
object OP_9 : ScriptElt()
object OP_10 : ScriptElt()
object OP_11 : ScriptElt()
object OP_12 : ScriptElt()
object OP_13 : ScriptElt()
object OP_14 : ScriptElt()
object OP_15 : ScriptElt()
object OP_16 : ScriptElt()
object OP_NOP : ScriptElt()
object OP_VER : ScriptElt()
object OP_IF : ScriptElt()
object OP_NOTIF : ScriptElt()
object OP_VERIF : ScriptElt()
object OP_VERNOTIF : ScriptElt()
object OP_ELSE : ScriptElt()
object OP_ENDIF : ScriptElt()
object OP_VERIFY : ScriptElt()
object OP_RETURN : ScriptElt()
object OP_TOALTSTACK : ScriptElt()
object OP_FROMALTSTACK : ScriptElt()
object OP_2DROP : ScriptElt()
object OP_2DUP : ScriptElt()
object OP_3DUP : ScriptElt()
object OP_2OVER : ScriptElt()
object OP_2ROT : ScriptElt()
object OP_2SWAP : ScriptElt()
object OP_IFDUP : ScriptElt()
object OP_DEPTH : ScriptElt()
object OP_DROP : ScriptElt()
object OP_DUP : ScriptElt()
object OP_NIP : ScriptElt()
object OP_OVER : ScriptElt()
object OP_PICK : ScriptElt()
object OP_ROLL : ScriptElt()
object OP_ROT : ScriptElt()
object OP_SWAP : ScriptElt()
object OP_TUCK : ScriptElt()
object OP_CAT : ScriptElt()
object OP_SUBSTR : ScriptElt()
object OP_LEFT : ScriptElt()
object OP_RIGHT : ScriptElt()
object OP_SIZE : ScriptElt()
object OP_INVERT : ScriptElt()
object OP_AND : ScriptElt()
object OP_OR : ScriptElt()
object OP_XOR : ScriptElt()
object OP_EQUAL : ScriptElt()
object OP_EQUALVERIFY : ScriptElt()
object OP_RESERVED1 : ScriptElt()
object OP_RESERVED2 : ScriptElt()
object OP_1ADD : ScriptElt()
object OP_1SUB : ScriptElt()
object OP_2MUL : ScriptElt()
object OP_2DIV : ScriptElt()
object OP_NEGATE : ScriptElt()
object OP_ABS : ScriptElt()
object OP_NOT : ScriptElt()
object OP_0NOTEQUAL : ScriptElt()
object OP_ADD : ScriptElt()
object OP_SUB : ScriptElt()
object OP_MUL : ScriptElt()
object OP_DIV : ScriptElt()
object OP_MOD : ScriptElt()
object OP_LSHIFT : ScriptElt()
object OP_RSHIFT : ScriptElt()
object OP_BOOLAND : ScriptElt()
object OP_BOOLOR : ScriptElt()
object OP_NUMEQUAL : ScriptElt()
object OP_NUMEQUALVERIFY : ScriptElt()
object OP_NUMNOTEQUAL : ScriptElt()
object OP_LESSTHAN : ScriptElt()
object OP_GREATERTHAN : ScriptElt()
object OP_LESSTHANOREQUAL : ScriptElt()
object OP_GREATERTHANOREQUAL : ScriptElt()
object OP_MIN : ScriptElt()
object OP_MAX : ScriptElt()
object OP_WITHIN : ScriptElt()
object OP_RIPEMD160 : ScriptElt()
object OP_SHA1 : ScriptElt()
object OP_SHA256 : ScriptElt()
object OP_HASH160 : ScriptElt()
object OP_HASH256 : ScriptElt()
object OP_CODESEPARATOR : ScriptElt()
object OP_CHECKSIG : ScriptElt()
object OP_CHECKSIGVERIFY : ScriptElt()
object OP_CHECKMULTISIG : ScriptElt()
object OP_CHECKMULTISIGVERIFY : ScriptElt()
object OP_NOP1 : ScriptElt()
object OP_CHECKLOCKTIMEVERIFY : ScriptElt()
object OP_CHECKSEQUENCEVERIFY : ScriptElt()
object OP_NOP4 : ScriptElt()
object OP_NOP5 : ScriptElt()
object OP_NOP6 : ScriptElt()
object OP_NOP7 : ScriptElt()
object OP_NOP8 : ScriptElt()
object OP_NOP9 : ScriptElt()
object OP_NOP10 : ScriptElt()
object OP_SMALLINTEGER : ScriptElt()
object OP_INVALIDOPCODE : ScriptElt()
// @formatter:on

data class OP_PUSHDATA(@JvmField val data: ByteVector, @JvmField val code: Int) : ScriptElt() {
    constructor(data: ByteArray, code: Int) : this(data.byteVector(), code)

    constructor(data: ByteArray) : this(
        data,
        codeFromDataLength(data.count())
    )

    constructor(data: ByteVector) : this(
        data,
        codeFromDataLength(data.size())
    )

    constructor(data: ByteVector32) : this(
        data,
        codeFromDataLength(data.size())
    )

    constructor(publicKey: PublicKey) : this(publicKey.value)

    companion object {
        @JvmStatic
        fun codeFromDataLength(length: Int): Int {
            val code = when {
                length < 0x4c -> length
                length < 0xff -> 0x4c
                length < 0xffff -> 0x4d
                length < 0xffffffff -> 0x4e
                else -> {
                    throw IllegalArgumentException("data length is $length}, too big for OP_PUSHDATA")
                }
            }
            return code
        }

        @JvmStatic
        fun isMinimal(data: ByteArray, code: Int): Boolean {
            return when {
                data.size == 0 -> code == ScriptEltMapping.elt2code[OP_0]
                data.size == 1 && data[0] >= 1 && data[0] <= 16 -> code == (ScriptEltMapping.elt2code[OP_1])?.plus(data[0] - 1)
                data.size == 1 && data[0] == 0x81.toByte() -> code == ScriptEltMapping.elt2code[OP_1NEGATE]
                data.size <= 75 -> code == data.size
                data.size <= 255 -> code == ScriptEltMapping.elt2code[OP_PUSHDATA1]
                data.size <= 65535 -> code == ScriptEltMapping.elt2code[OP_PUSHDATA2]
                else -> {
                    true
                }
            }
        }
    }
}

data class OP_INVALID(val code: Int) : ScriptElt()

object ScriptEltMapping {
    // code -> ScriptElt
    @JvmField
    val code2elt = hashMapOf(
        0x00 to OP_0,
        0x4c to OP_PUSHDATA1,
        0x4d to OP_PUSHDATA2,
        0x4e to OP_PUSHDATA4,
        0x4f to OP_1NEGATE,
        0x50 to OP_RESERVED,
        0x51 to OP_1,
        0x52 to OP_2,
        0x53 to OP_3,
        0x54 to OP_4,
        0x55 to OP_5,
        0x56 to OP_6,
        0x57 to OP_7,
        0x58 to OP_8,
        0x59 to OP_9,
        0x5a to OP_10,
        0x5b to OP_11,
        0x5c to OP_12,
        0x5d to OP_13,
        0x5e to OP_14,
        0x5f to OP_15,
        0x60 to OP_16,
        0x61 to OP_NOP,
        0x62 to OP_VER,
        0x63 to OP_IF,
        0x64 to OP_NOTIF,
        0x65 to OP_VERIF,
        0x66 to OP_VERNOTIF,
        0x67 to OP_ELSE,
        0x68 to OP_ENDIF,
        0x69 to OP_VERIFY,
        0x6a to OP_RETURN,
        0x6b to OP_TOALTSTACK,
        0x6c to OP_FROMALTSTACK,
        0x6d to OP_2DROP,
        0x6e to OP_2DUP,
        0x6f to OP_3DUP,
        0x70 to OP_2OVER,
        0x71 to OP_2ROT,
        0x72 to OP_2SWAP,
        0x73 to OP_IFDUP,
        0x74 to OP_DEPTH,
        0x75 to OP_DROP,
        0x76 to OP_DUP,
        0x77 to OP_NIP,
        0x78 to OP_OVER,
        0x79 to OP_PICK,
        0x7a to OP_ROLL,
        0x7b to OP_ROT,
        0x7c to OP_SWAP,
        0x7d to OP_TUCK,
        0x7e to OP_CAT,
        0x7f to OP_SUBSTR,
        0x80 to OP_LEFT,
        0x81 to OP_RIGHT,
        0x82 to OP_SIZE,
        0x83 to OP_INVERT,
        0x84 to OP_AND,
        0x85 to OP_OR,
        0x86 to OP_XOR,
        0x87 to OP_EQUAL,
        0x88 to OP_EQUALVERIFY,
        0x89 to OP_RESERVED1,
        0x8a to OP_RESERVED2,
        0x8b to OP_1ADD,
        0x8c to OP_1SUB,
        0x8d to OP_2MUL,
        0x8e to OP_2DIV,
        0x8f to OP_NEGATE,
        0x90 to OP_ABS,
        0x91 to OP_NOT,
        0x92 to OP_0NOTEQUAL,
        0x93 to OP_ADD,
        0x94 to OP_SUB,
        0x95 to OP_MUL,
        0x96 to OP_DIV,
        0x97 to OP_MOD,
        0x98 to OP_LSHIFT,
        0x99 to OP_RSHIFT,
        0x9a to OP_BOOLAND,
        0x9b to OP_BOOLOR,
        0x9c to OP_NUMEQUAL,
        0x9d to OP_NUMEQUALVERIFY,
        0x9e to OP_NUMNOTEQUAL,
        0x9f to OP_LESSTHAN,
        0xa0 to OP_GREATERTHAN,
        0xa1 to OP_LESSTHANOREQUAL,
        0xa2 to OP_GREATERTHANOREQUAL,
        0xa3 to OP_MIN,
        0xa4 to OP_MAX,
        0xa5 to OP_WITHIN,
        0xa6 to OP_RIPEMD160,
        0xa7 to OP_SHA1,
        0xa8 to OP_SHA256,
        0xa9 to OP_HASH160,
        0xaa to OP_HASH256,
        0xab to OP_CODESEPARATOR,
        0xac to OP_CHECKSIG,
        0xad to OP_CHECKSIGVERIFY,
        0xae to OP_CHECKMULTISIG,
        0xaf to OP_CHECKMULTISIGVERIFY,
        0xb0 to OP_NOP1,
        0xb1 to OP_CHECKLOCKTIMEVERIFY,
        0xb2 to OP_CHECKSEQUENCEVERIFY,
        0xb3 to OP_NOP4,
        0xb4 to OP_NOP5,
        0xb5 to OP_NOP6,
        0xb6 to OP_NOP7,
        0xb7 to OP_NOP8,
        0xb8 to OP_NOP9,
        0xb9 to OP_NOP10,
        0xfa to OP_SMALLINTEGER,
        0xff to OP_INVALIDOPCODE
    )

    @JvmField
    val elt2code = code2elt.map { it -> it.value to it.key }.toMap()

    fun name(elt: ScriptElt): String {
        val name = elt.toString().removePrefix("fr.acinq.bitcoin.OP_")
        val name1 = name.take(name.lastIndexOf('@'))
        return name1
    }

    val name2code = elt2code.map { it ->
        name(
            it.key
        ) to it.value
    }.toMap() + mapOf<String, Int>("NOP2" to 0xb1, "NOP3" to 0xb2)
}