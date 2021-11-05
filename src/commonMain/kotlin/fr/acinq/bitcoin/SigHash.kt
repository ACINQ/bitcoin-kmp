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

import kotlin.jvm.JvmStatic

public object SigHash {
    public const val SIGHASH_ALL: Int = 1
    public const val SIGHASH_NONE: Int = 2
    public const val SIGHASH_SINGLE: Int = 3
    public const val SIGHASH_ANYONECANPAY: Int = 0x80
    public const val SIGHASH_DEFAULT: Int = 0 //!< Taproot only; implied when sighash byte is missing, and equivalent to SIGHASH_ALL
    public const val SIGHASH_OUTPUT_MASK: Int = 3
    public const val SIGHASH_INPUT_MASK: Int = 0x80

    @JvmStatic
    public fun isAnyoneCanPay(sighashType: Int): Boolean = (sighashType and SIGHASH_ANYONECANPAY) != 0

    @JvmStatic
    public fun isHashSingle(sighashType: Int): Boolean = (sighashType and 0x1f) == SIGHASH_SINGLE

    @JvmStatic
    public fun isHashNone(sighashType: Int): Boolean = (sighashType and 0x1f) == SIGHASH_NONE
}

public object SigVersion {
    public const val SIGVERSION_BASE: Int = 0
    public const val SIGVERSION_WITNESS_V0: Int = 1
    public const val SIGVERSION_TAPROOT: Int = 2
    public const val SIGVERSION_TAPSCRIPT: Int = 3
}
