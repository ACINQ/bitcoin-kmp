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

public expect object Secp256k1 {
    public fun computePublicKey(priv: ByteArray): ByteArray

    public fun parsePublicKey(pub: ByteArray): ByteArray

    public fun ecdh(priv: ByteArray, pub: ByteArray): ByteArray

    public fun privateKeyAdd(priv1: ByteArray, priv2: ByteArray): ByteArray

    public fun privateKeyNegate(priv: ByteArray): ByteArray

    public fun privateKeyMul(priv: ByteArray, tweak: ByteArray): ByteArray

    public fun publicKeyAdd(pub1: ByteArray, pub2: ByteArray): ByteArray

    public fun publicKeyNegate(pub: ByteArray): ByteArray

    public fun publicKeyMul(pub: ByteArray, tweak: ByteArray): ByteArray

    public fun sign(data: ByteArray, priv: ByteArray): ByteArray

    public fun verify(data: ByteArray, sig: ByteArray, pub: ByteArray): Boolean

    public fun compact2der(input: ByteArray): ByteArray

    public fun der2compact(input: ByteArray): ByteArray

    public fun signatureNormalize(input: ByteArray): Pair<ByteArray, Boolean>

    public fun recoverPublicKey(sig: ByteArray, message: ByteArray, recid: Int): ByteArray
}