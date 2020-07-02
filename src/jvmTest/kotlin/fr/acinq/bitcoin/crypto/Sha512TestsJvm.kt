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

import fr.acinq.bitcoin.Hex
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertTrue

@OptIn(ExperimentalStdlibApi::class)
class Sha512TestsJvm {
    @Test @Ignore
    fun `very long input`() {
        val sha512 = Sha512()
        val input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".encodeToByteArray()
        for (i in 0L until 16_777_216L) sha512.update(input, 0, input.size)
        val output = ByteArray(64)
        sha512.doFinal(output, 0)
        assertTrue { output.contentEquals(Hex.decode("b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086")) }
    }
}