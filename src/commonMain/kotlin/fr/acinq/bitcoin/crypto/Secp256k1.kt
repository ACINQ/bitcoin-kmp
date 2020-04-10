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

package fr.acinq.bitcoin.crypto

expect object Secp256k1 {
    fun computePublicKey(priv: ByteArray): ByteArray

    fun parsePublicKey(pub: ByteArray): ByteArray

    fun ecdh(priv: ByteArray, pub: ByteArray): ByteArray

    fun privateKeyAdd(priv1: ByteArray, priv2: ByteArray): ByteArray

    fun privateKeyNegate(priv: ByteArray): ByteArray

    fun privateKeyMul(priv: ByteArray, tweak: ByteArray): ByteArray

    fun publicKeyAdd(pub1: ByteArray, pub2: ByteArray): ByteArray

    fun publicKeyNegate(pub: ByteArray): ByteArray

    fun publicKeyMul(pub: ByteArray, tweak: ByteArray): ByteArray

    fun sign(data: ByteArray, priv: ByteArray): ByteArray

    fun verify(data: ByteArray, sig: ByteArray, pub: ByteArray): Boolean

    fun compact2der(input: ByteArray): ByteArray

    fun der2compact(input: ByteArray): ByteArray

    fun signatureNormalize(input: ByteArray): Pair<ByteArray, Boolean>

    fun recoverPublicKey(sig: ByteArray, message: ByteArray, recid: Int): ByteArray
}