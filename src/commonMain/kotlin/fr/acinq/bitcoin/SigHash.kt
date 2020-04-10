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

object SigHash {
    const val SIGHASH_ALL = 1
    const val SIGHASH_NONE = 2
    const val SIGHASH_SINGLE = 3
    const val SIGHASH_ANYONECANPAY = 0x80

    fun isAnyoneCanPay(sighashType: Int): Boolean = (sighashType and SIGHASH_ANYONECANPAY) != 0

    fun isHashSingle(sighashType: Int): Boolean = (sighashType and 0x1f) == SIGHASH_SINGLE

    fun isHashNone(sighashType: Int): Boolean = (sighashType and 0x1f) == SIGHASH_NONE
}

object SigVersion {
    const val SIGVERSION_BASE = 0
    const val SIGVERSION_WITNESS_V0 = 1
}
