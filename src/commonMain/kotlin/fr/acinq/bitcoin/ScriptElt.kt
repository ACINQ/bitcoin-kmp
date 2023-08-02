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
    public abstract val code: Int

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
public object OP_0 : ScriptElt() {
    override val code: Int get() = 0x00
}
public object OP_PUSHDATA1 : ScriptElt() {
    override val code: Int get() = 0x4c
}
public object OP_PUSHDATA2 : ScriptElt() {
    override val code: Int get() = 0x4d
}
public object OP_PUSHDATA4 : ScriptElt() {
    override val code: Int get() = 0x4e
}
public object OP_1NEGATE : ScriptElt() {
    override val code: Int get() = 0x4f
}
public object OP_RESERVED : ScriptElt() {
    override val code: Int get() = 0x50
}
public object OP_1 : ScriptElt() {
    override val code: Int get() = 0x51
}
public object OP_2 : ScriptElt() {
    override val code: Int get() = 0x52
}
public object OP_3 : ScriptElt() {
    override val code: Int get() = 0x53
}
public object OP_4 : ScriptElt() {
    override val code: Int get() = 0x54
}
public object OP_5 : ScriptElt() {
    override val code: Int get() = 0x55
}
public object OP_6 : ScriptElt() {
    override val code: Int get() = 0x56
}
public object OP_7 : ScriptElt() {
    override val code: Int get() = 0x57
}
public object OP_8 : ScriptElt() {
    override val code: Int get() = 0x58
}
public object OP_9 : ScriptElt() {
    override val code: Int get() = 0x59
}
public object OP_10 : ScriptElt() {
    override val code: Int get() = 0x5a
}
public object OP_11 : ScriptElt() {
    override val code: Int get() = 0x5b
}
public object OP_12 : ScriptElt() {
    override val code: Int get() = 0x5c
}
public object OP_13 : ScriptElt() {
    override val code: Int get() = 0x5d
}
public object OP_14 : ScriptElt() {
    override val code: Int get() = 0x5e
}
public object OP_15 : ScriptElt() {
    override val code: Int get() = 0x5f
}
public object OP_16 : ScriptElt() {
    override val code: Int get() = 0x60
}
public object OP_NOP : ScriptElt() {
    override val code: Int get() = 0x61
}
public object OP_VER : ScriptElt() {
    override val code: Int get() = 0x62
}
public object OP_IF : ScriptElt() {
    override val code: Int get() = 0x63
}
public object OP_NOTIF : ScriptElt() {
    override val code: Int get() = 0x64
}
public object OP_VERIF : ScriptElt() {
    override val code: Int get() = 0x65
}
public object OP_VERNOTIF : ScriptElt() {
    override val code: Int get() = 0x66
}
public object OP_ELSE : ScriptElt() {
    override val code: Int get() = 0x67
}
public object OP_ENDIF : ScriptElt() {
    override val code: Int get() = 0x68
}
public object OP_VERIFY : ScriptElt() {
    override val code: Int get() = 0x69
}
public object OP_RETURN : ScriptElt() {
    override val code: Int get() = 0x6a
}
public object OP_TOALTSTACK : ScriptElt() {
    override val code: Int get() = 0x6b
}
public object OP_FROMALTSTACK : ScriptElt() {
    override val code: Int get() = 0x6c
}
public object OP_2DROP : ScriptElt() {
    override val code: Int get() = 0x6d
}
public object OP_2DUP : ScriptElt() {
    override val code: Int get() = 0x6e
}
public object OP_3DUP : ScriptElt() {
    override val code: Int get() = 0x6f
}
public object OP_2OVER : ScriptElt() {
    override val code: Int get() = 0x70
}
public object OP_2ROT : ScriptElt() {
    override val code: Int get() = 0x71
}
public object OP_2SWAP : ScriptElt() {
    override val code: Int get() = 0x72
}
public object OP_IFDUP : ScriptElt() {
    override val code: Int get() = 0x73
}
public object OP_DEPTH : ScriptElt() {
    override val code: Int get() = 0x74
}
public object OP_DROP : ScriptElt() {
    override val code: Int get() = 0x75
}
public object OP_DUP : ScriptElt() {
    override val code: Int get() = 0x76
}
public object OP_NIP : ScriptElt() {
    override val code: Int get() = 0x77
}
public object OP_OVER : ScriptElt() {
    override val code: Int get() = 0x78
}
public object OP_PICK : ScriptElt() {
    override val code: Int get() = 0x79
}
public object OP_ROLL : ScriptElt() {
    override val code: Int get() = 0x7a
}
public object OP_ROT : ScriptElt() {
    override val code: Int get() = 0x7b
}
public object OP_SWAP : ScriptElt() {
    override val code: Int get() = 0x7c
}
public object OP_TUCK : ScriptElt() {
    override val code: Int get() = 0x7d
}
public object OP_CAT : ScriptElt() {
    override val code: Int get() = 0x7e
}
public object OP_SUBSTR : ScriptElt() {
    override val code: Int get() = 0x7f
}
public object OP_LEFT : ScriptElt() {
    override val code: Int get() = 0x80
}
public object OP_RIGHT : ScriptElt() {
    override val code: Int get() = 0x81
}
public object OP_SIZE : ScriptElt() {
    override val code: Int get() = 0x82
}
public object OP_INVERT : ScriptElt() {
    override val code: Int get() = 0x83
}
public object OP_AND : ScriptElt() {
    override val code: Int get() = 0x84
}
public object OP_OR : ScriptElt() {
    override val code: Int get() = 0x85
}
public object OP_XOR : ScriptElt() {
    override val code: Int get() = 0x86
}
public object OP_EQUAL : ScriptElt() {
    override val code: Int get() = 0x87
}
public object OP_EQUALVERIFY : ScriptElt() {
    override val code: Int get() = 0x88
}
public object OP_RESERVED1 : ScriptElt() {
    override val code: Int get() = 0x89
}
public object OP_RESERVED2 : ScriptElt() {
    override val code: Int get() = 0x8a
}
public object OP_1ADD : ScriptElt() {
    override val code: Int get() = 0x8b
}
public object OP_1SUB : ScriptElt() {
    override val code: Int get() = 0x8c
}
public object OP_2MUL : ScriptElt() {
    override val code: Int get() = 0x8d
}
public object OP_2DIV : ScriptElt() {
    override val code: Int get() = 0x8e
}
public object OP_NEGATE : ScriptElt() {
    override val code: Int get() = 0x8f
}
public object OP_ABS : ScriptElt() {
    override val code: Int get() = 0x90
}
public object OP_NOT : ScriptElt() {
    override val code: Int get() = 0x91
}
public object OP_0NOTEQUAL : ScriptElt() {
    override val code: Int get() = 0x92
}
public object OP_ADD : ScriptElt() {
    override val code: Int get() = 0x93
}
public object OP_SUB : ScriptElt() {
    override val code: Int get() = 0x94
}
public object OP_MUL : ScriptElt() {
    override val code: Int get() = 0x95
}
public object OP_DIV : ScriptElt() {
    override val code: Int get() = 0x96
}
public object OP_MOD : ScriptElt() {
    override val code: Int get() = 0x97
}
public object OP_LSHIFT : ScriptElt() {
    override val code: Int get() = 0x98
}
public object OP_RSHIFT : ScriptElt() {
    override val code: Int get() = 0x99
}
public object OP_BOOLAND : ScriptElt() {
    override val code: Int get() = 0x9a
}
public object OP_BOOLOR : ScriptElt() {
    override val code: Int get() = 0x9b
}
public object OP_NUMEQUAL : ScriptElt() {
    override val code: Int get() = 0x9c
}
public object OP_NUMEQUALVERIFY : ScriptElt() {
    override val code: Int get() = 0x9d
}
public object OP_NUMNOTEQUAL : ScriptElt() {
    override val code: Int get() = 0x9e
}
public object OP_LESSTHAN : ScriptElt() {
    override val code: Int get() = 0x9f
}
public object OP_GREATERTHAN : ScriptElt() {
    override val code: Int get() = 0xa0
}
public object OP_LESSTHANOREQUAL : ScriptElt() {
    override val code: Int get() = 0xa1
}
public object OP_GREATERTHANOREQUAL : ScriptElt() {
    override val code: Int get() = 0xa2
}
public object OP_MIN : ScriptElt() {
    override val code: Int get() = 0xa3
}
public object OP_MAX : ScriptElt() {
    override val code: Int get() = 0xa4
}
public object OP_WITHIN : ScriptElt() {
    override val code: Int get() = 0xa5
}
public object OP_RIPEMD160 : ScriptElt() {
    override val code: Int get() = 0xa6
}
public object OP_SHA1 : ScriptElt() {
    override val code: Int get() = 0xa7
}
public object OP_SHA256 : ScriptElt() {
    override val code: Int get() = 0xa8
}
public object OP_HASH160 : ScriptElt() {
    override val code: Int get() = 0xa9
}
public object OP_HASH256 : ScriptElt() {
    override val code: Int get() = 0xaa
}
public object OP_CODESEPARATOR : ScriptElt() {
    override val code: Int get() = 0xab
}
public object OP_CHECKSIG : ScriptElt() {
    override val code: Int get() = 0xac
}
public object OP_CHECKSIGVERIFY : ScriptElt() {
    override val code: Int get() = 0xad
}
public object OP_CHECKMULTISIG : ScriptElt() {
    override val code: Int get() = 0xae
}
public object OP_CHECKMULTISIGVERIFY : ScriptElt() {
    override val code: Int get() = 0xaf
}
public object OP_NOP1 : ScriptElt() {
    override val code: Int get() = 0xb0
}
public object OP_CHECKLOCKTIMEVERIFY : ScriptElt() {
    override val code: Int get() = 0xb1
}
public object OP_CHECKSEQUENCEVERIFY : ScriptElt() {
    override val code: Int get() = 0xb2
}
public object OP_NOP4 : ScriptElt() {
    override val code: Int get() = 0xb3
}
public object OP_NOP5 : ScriptElt() {
    override val code: Int get() = 0xb4
}
public object OP_NOP6 : ScriptElt() {
    override val code: Int get() = 0xb5
}
public object OP_NOP7 : ScriptElt() {
    override val code: Int get() = 0xb6
}
public object OP_NOP8 : ScriptElt() {
    override val code: Int get() = 0xb7
}
public object OP_NOP9 : ScriptElt() {
    override val code: Int get() = 0xb8
}
public object OP_NOP10 : ScriptElt() {
    override val code: Int get() = 0xb9
}
// Opcode added by BIP 342 (Tapscript)
public object OP_CHECKSIGADD: ScriptElt() {
    override val code: Int get() = 0xba
}

public object OP_INVALIDOPCODE : ScriptElt() {
    override val code: Int get() = 0xff
}
// @formatter:on

public data class OP_PUSHDATA(@JvmField val data: ByteVector, @JvmField val opCode: Int) : ScriptElt() {
    override val code: Int get() = opCode

    public constructor(data: ByteArray, code: Int) : this(data.byteVector(), code)

    public constructor(data: ByteArray) : this(data, codeFromDataLength(data.count()))

    public constructor(data: ByteVector) : this(data, codeFromDataLength(data.size()))

    public constructor(data: ByteVector32) : this(data, codeFromDataLength(data.size()))

    public constructor(publicKey: PublicKey) : this(publicKey.value)

    public constructor(publicKey: XonlyPublicKey) : this(publicKey.value)

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
                data.isEmpty() -> code == OP_0.code
                data.size == 1 && data[0] >= 1 && data[0] <= 16 -> code == (OP_1.code).plus(data[0] - 1)
                data.size == 1 && data[0] == 0x81.toByte() -> code == OP_1NEGATE.code
                data.size <= 75 -> code == data.size
                data.size <= 255 -> code == OP_PUSHDATA1.code
                data.size <= 65535 -> code == OP_PUSHDATA2.code
                else -> {
                    true
                }
            }
        }
    }
}

public data class OP_INVALID(override val code: Int) : ScriptElt()

public object ScriptEltMapping {
    public val elements: List<ScriptElt> = listOf(
        OP_0,
        OP_PUSHDATA1,
        OP_PUSHDATA2,
        OP_PUSHDATA4,
        OP_1NEGATE,
        OP_RESERVED,
        OP_1,
        OP_2,
        OP_3,
        OP_4,
        OP_5,
        OP_6,
        OP_7,
        OP_8,
        OP_9,
        OP_10,
        OP_11,
        OP_12,
        OP_13,
        OP_14,
        OP_15,
        OP_16,
        OP_NOP,
        OP_VER,
        OP_IF,
        OP_NOTIF,
        OP_VERIF,
        OP_VERNOTIF,
        OP_ELSE,
        OP_ENDIF,
        OP_VERIFY,
        OP_RETURN,
        OP_TOALTSTACK,
        OP_FROMALTSTACK,
        OP_2DROP,
        OP_2DUP,
        OP_3DUP,
        OP_2OVER,
        OP_2ROT,
        OP_2SWAP,
        OP_IFDUP,
        OP_DEPTH,
        OP_DROP,
        OP_DUP,
        OP_NIP,
        OP_OVER,
        OP_PICK,
        OP_ROLL,
        OP_ROT,
        OP_SWAP,
        OP_TUCK,
        OP_CAT,
        OP_SUBSTR,
        OP_LEFT,
        OP_RIGHT,
        OP_SIZE,
        OP_INVERT,
        OP_AND,
        OP_OR,
        OP_XOR,
        OP_EQUAL,
        OP_EQUALVERIFY,
        OP_RESERVED1,
        OP_RESERVED2,
        OP_1ADD,
        OP_1SUB,
        OP_2MUL,
        OP_2DIV,
        OP_NEGATE,
        OP_ABS,
        OP_NOT,
        OP_0NOTEQUAL,
        OP_ADD,
        OP_SUB,
        OP_MUL,
        OP_DIV,
        OP_MOD,
        OP_LSHIFT,
        OP_RSHIFT,
        OP_BOOLAND,
        OP_BOOLOR,
        OP_NUMEQUAL,
        OP_NUMEQUALVERIFY,
        OP_NUMNOTEQUAL,
        OP_LESSTHAN,
        OP_GREATERTHAN,
        OP_LESSTHANOREQUAL,
        OP_GREATERTHANOREQUAL,
        OP_MIN,
        OP_MAX,
        OP_WITHIN,
        OP_RIPEMD160,
        OP_SHA1,
        OP_SHA256,
        OP_HASH160,
        OP_HASH256,
        OP_CODESEPARATOR,
        OP_CHECKSIG,
        OP_CHECKSIGVERIFY,
        OP_CHECKMULTISIG,
        OP_CHECKMULTISIGVERIFY,
        OP_NOP1,
        OP_CHECKLOCKTIMEVERIFY,
        OP_CHECKSEQUENCEVERIFY,
        OP_NOP4,
        OP_NOP5,
        OP_NOP6,
        OP_NOP7,
        OP_NOP8,
        OP_NOP9,
        OP_NOP10,
        OP_CHECKSIGADD,
        OP_INVALIDOPCODE
    )
    // code -> ScriptElt
    @JvmField
    public val code2elt: Map<Int, ScriptElt> = elements.associateBy { it.code }

    public fun name(elt: ScriptElt): String {
        val name = elt.toString().removePrefix("fr.acinq.bitcoin.OP_")
        val name1 = name.take(name.lastIndexOf('@'))
        return name1
    }

    public val name2code: Map<String, Int> = elements.associate { name(it) to it.code }
}