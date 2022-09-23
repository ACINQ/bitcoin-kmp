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

public data class XonlyPublicKey(@JvmField val value: ByteVector32) {
    public constructor(pub: PublicKey) : this(pub.value.drop(1).toByteArray().byteVector32())

    val publicKey: PublicKey get() = PublicKey(byteArrayOf(2) + value.toByteArray())

    public fun tweak(merkleRoot: ByteVector32?): ByteVector32 {
        return Crypto.taggedHash(this.value.toByteArray() + (merkleRoot?.toByteArray() ?: ByteArray(0)), "TapTweak")
    }

    public fun outputKey(merkleRoot: ByteVector32?): XonlyPublicKey = this + PrivateKey(tweak(merkleRoot)).publicKey()

    public operator fun plus(that: PublicKey): XonlyPublicKey {
        val pub = publicKey + that
        return XonlyPublicKey(pub)
    }
}
