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

public sealed class ScriptElt {
    public fun isPush(size: Int): Boolean = isPush(this, size)

    public fun isPush(): Boolean = isPush(this)

    public companion object {
        @JvmStatic
        public fun isPush(op: ScriptElt): Boolean {
            return when {
                op is OP_PUSHDATA -> true
                else -> false
            }
        }

        @JvmStatic
        public fun isPush(op: ScriptElt, size: Int): Boolean {
            return when {
                op is OP_PUSHDATA && op.data.size() == size -> true
                else -> false
            }
        }
    }
}

// @formatter:off
public object OP_0 : ScriptElt()
public object OP_PUSHDATA1 : ScriptElt()
public object OP_PUSHDATA2 : ScriptElt()
public object OP_PUSHDATA4 : ScriptElt()
public object OP_1NEGATE : ScriptElt()
public object OP_RESERVED : ScriptElt()
public object OP_1 : ScriptElt()
public object OP_2 : ScriptElt()
public object OP_3 : ScriptElt()
public object OP_4 : ScriptElt()
public object OP_5 : ScriptElt()
public object OP_6 : ScriptElt()
public object OP_7 : ScriptElt()
public object OP_8 : ScriptElt()
public object OP_9 : ScriptElt()
public object OP_10 : ScriptElt()
public object OP_11 : ScriptElt()
public object OP_12 : ScriptElt()
public object OP_13 : ScriptElt()
public object OP_14 : ScriptElt()
public object OP_15 : ScriptElt()
public object OP_16 : ScriptElt()
public object OP_NOP : ScriptElt()
public object OP_VER : ScriptElt()
public object OP_IF : ScriptElt()
public object OP_NOTIF : ScriptElt()
public object OP_VERIF : ScriptElt()
public object OP_VERNOTIF : ScriptElt()
public object OP_ELSE : ScriptElt()
public object OP_ENDIF : ScriptElt()
public object OP_VERIFY : ScriptElt()
public object OP_RETURN : ScriptElt()
public object OP_TOALTSTACK : ScriptElt()
public object OP_FROMALTSTACK : ScriptElt()
public object OP_2DROP : ScriptElt()
public object OP_2DUP : ScriptElt()
public object OP_3DUP : ScriptElt()
public object OP_2OVER : ScriptElt()
public object OP_2ROT : ScriptElt()
public object OP_2SWAP : ScriptElt()
public object OP_IFDUP : ScriptElt()
public object OP_DEPTH : ScriptElt()
public object OP_DROP : ScriptElt()
public object OP_DUP : ScriptElt()
public object OP_NIP : ScriptElt()
public object OP_OVER : ScriptElt()
public object OP_PICK : ScriptElt()
public object OP_ROLL : ScriptElt()
public object OP_ROT : ScriptElt()
public object OP_SWAP : ScriptElt()
public object OP_TUCK : ScriptElt()
public object OP_CAT : ScriptElt()
public object OP_SUBSTR : ScriptElt()
public object OP_LEFT : ScriptElt()
public object OP_RIGHT : ScriptElt()
public object OP_SIZE : ScriptElt()
public object OP_INVERT : ScriptElt()
public object OP_AND : ScriptElt()
public object OP_OR : ScriptElt()
public object OP_XOR : ScriptElt()
public object OP_EQUAL : ScriptElt()
public object OP_EQUALVERIFY : ScriptElt()
public object OP_RESERVED1 : ScriptElt()
public object OP_RESERVED2 : ScriptElt()
public object OP_1ADD : ScriptElt()
public object OP_1SUB : ScriptElt()
public object OP_2MUL : ScriptElt()
public object OP_2DIV : ScriptElt()
public object OP_NEGATE : ScriptElt()
public object OP_ABS : ScriptElt()
public object OP_NOT : ScriptElt()
public object OP_0NOTEQUAL : ScriptElt()
public object OP_ADD : ScriptElt()
public object OP_SUB : ScriptElt()
public object OP_MUL : ScriptElt()
public object OP_DIV : ScriptElt()
public object OP_MOD : ScriptElt()
public object OP_LSHIFT : ScriptElt()
public object OP_RSHIFT : ScriptElt()
public object OP_BOOLAND : ScriptElt()
public object OP_BOOLOR : ScriptElt()
public object OP_NUMEQUAL : ScriptElt()
public object OP_NUMEQUALVERIFY : ScriptElt()
public object OP_NUMNOTEQUAL : ScriptElt()
public object OP_LESSTHAN : ScriptElt()
public object OP_GREATERTHAN : ScriptElt()
public object OP_LESSTHANOREQUAL : ScriptElt()
public object OP_GREATERTHANOREQUAL : ScriptElt()
public object OP_MIN : ScriptElt()
public object OP_MAX : ScriptElt()
public object OP_WITHIN : ScriptElt()
public object OP_RIPEMD160 : ScriptElt()
public object OP_SHA1 : ScriptElt()
public object OP_SHA256 : ScriptElt()
public object OP_HASH160 : ScriptElt()
public object OP_HASH256 : ScriptElt()
public object OP_CODESEPARATOR : ScriptElt()
public object OP_CHECKSIG : ScriptElt()
public object OP_CHECKSIGVERIFY : ScriptElt()
public object OP_CHECKMULTISIG : ScriptElt()
public object OP_CHECKMULTISIGVERIFY : ScriptElt()
public object OP_NOP1 : ScriptElt()
public object OP_CHECKLOCKTIMEVERIFY : ScriptElt()
public object OP_CHECKSEQUENCEVERIFY : ScriptElt()
public object OP_NOP4 : ScriptElt()
public object OP_NOP5 : ScriptElt()
public object OP_NOP6 : ScriptElt()
public object OP_NOP7 : ScriptElt()
public object OP_NOP8 : ScriptElt()
public object OP_NOP9 : ScriptElt()
public object OP_NOP10 : ScriptElt()
public object OP_SMALLINTEGER : ScriptElt()
public object OP_INVALIDOPCODE : ScriptElt()
// @formatter:on

public data class OP_PUSHDATA(@JvmField val data: ByteVector, @JvmField val code: Int) : ScriptElt() {
    public constructor(data: ByteArray, code: Int) : this(data.byteVector(), code)

    public constructor(data: ByteArray) : this(data, codeFromDataLength(data.count()))

    public constructor(data: ByteVector) : this(data, codeFromDataLength(data.size()))

    public constructor(data: ByteVector32) : this(data, codeFromDataLength(data.size()))

    public constructor(publicKey: PublicKey) : this(publicKey.value)

    public companion object {
        @JvmStatic
        public fun codeFromDataLength(length: Int): Int {
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
        public fun isMinimal(data: ByteArray, code: Int): Boolean {
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

public data class OP_INVALID(val code: Int) : ScriptElt()

public object ScriptEltMapping {
    // code -> ScriptElt
    @JvmField
    public val code2elt: HashMap<Int, ScriptElt> = hashMapOf(
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
    public val elt2code: Map<ScriptElt, Int> = code2elt.map { it.value to it.key }.toMap()

    public fun name(elt: ScriptElt): String {
        val name = elt.toString().removePrefix("fr.acinq.bitcoin.OP_")
        val name1 = name.take(name.lastIndexOf('@'))
        return name1
    }

    public val name2code: Map<String, Int> = elt2code.map { name(it.key) to it.value }.toMap() + mapOf<String, Int>("NOP2" to 0xb1, "NOP3" to 0xb2)
}