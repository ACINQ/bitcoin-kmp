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

import fr.acinq.bitcoin.MnemonicCode
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class Pbkdf2TestsCommon {
    @Test
    fun generate() {
        val password =
            Hex.decode("6162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e2061626f7574")
        val salt = Hex.decode("6d6e656d6f6e6963")
        val result = Pbkdf2.withHmacSha512(password, salt, 2048, 64)
        assertEquals("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4", Hex.encode(result))
    }

    @Test
    fun `test vectors`() {
        // test vectors from https://github.com/brycx/Test-Vector-Generation/blob/master/PBKDF2/pbkdf2-hmac-sha2-test-vectors.md
        assertEquals("867f70cf1ade02cff3752599a3a53dc4af34c7a6", Hex.encode(Pbkdf2.withHmacSha512("password".encodeToByteArray(), "salt".encodeToByteArray(), 1, 20)))
        assertEquals("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e", Hex.encode(Pbkdf2.withHmacSha512("password".encodeToByteArray(), "salt".encodeToByteArray(), 2, 20)))
        assertEquals("d197b1b33db0143e018b12f3d1d1479e6cdebdcc", Hex.encode(Pbkdf2.withHmacSha512("password".encodeToByteArray(), "salt".encodeToByteArray(), 4096, 20)))
        assertEquals("8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868", Hex.encode(Pbkdf2.withHmacSha512("passwordPASSWORDpassword".encodeToByteArray(), "saltSALTsaltSALTsaltSALTsaltSALTsalt".encodeToByteArray(), 4096, 25)))
        assertEquals("9d9e9c4cd21fe4be24d5b8244c759665", Hex.encode(Pbkdf2.withHmacSha512("pass\u0000word".encodeToByteArray(), "sa\u0000lt".encodeToByteArray(), 4096, 16)))
        assertEquals(
            "c74319d99499fc3e9013acff597c23c5baf0a0bec5634c46b8352b793e324723d55caa76b2b25c43402dcfdc06cdcf66f95b7d0429420b39520006749c51a04ef3eb99e576617395a178ba33214793e48045132928a9e9bf2661769fdc668f31798597aaf6da70dd996a81019726084d70f152baed8aafe2227c07636c6ddece",
            Hex.encode(Pbkdf2.withHmacSha512("passwd".encodeToByteArray(), "salt".encodeToByteArray(), 1, 128))
        )
        assertEquals(
            "e6337d6fbeb645c794d4a9b5b75b7b30dac9ac50376a91df1f4460f6060d5addb2c1fd1f84409abacc67de7eb4056e6bb06c2d82c3ef4ccd1bded0f675ed97c65c33d39f81248454327aa6d03fd049fc5cbb2b5e6dac08e8ace996cdc960b1bd4530b7e754773d75f67a733fdb99baf6470e42ffcb753c15c352d4800fb6f9d6",
            Hex.encode(Pbkdf2.withHmacSha512("Password".encodeToByteArray(), "NaCl".encodeToByteArray(), 80000, 128))
        )
        assertEquals(
            "10176fb32cb98cd7bb31e2bb5c8f6e425c103333a2e496058e3fd2bd88f657485c89ef92daa0668316bc23ebd1ef88f6dd14157b2320b5d54b5f26377c5dc279b1dcdec044bd6f91b166917c80e1e99ef861b1d2c7bce1b961178125fb86867f6db489a2eae0022e7bc9cf421f044319fac765d70cb89b45c214590e2ffb2c2b565ab3b9d07571fde0027b1dc57f8fd25afa842c1056dd459af4074d7510a0c020b914a5e202445d4d3f151070589dd6a2554fc506018c4f001df6239643dc86771286ae4910769d8385531bba57544d63c3640b90c98f1445ebdd129475e02086b600f0beb5b05cc6ca9b3633b452b7dad634e9336f56ec4c3ac0b4fe54ced8",
            Hex.encode(Pbkdf2.withHmacSha512("Password".encodeToByteArray(), "sa\u0000lt".encodeToByteArray(), 4096, 256))
        )
    }

    @Test
    fun `invalid parameters`() {
        val password = "password".encodeToByteArray()
        val salt = "salt".encodeToByteArray()
        assertFails { Pbkdf2.withHmacSha512(password, salt, 0, 64) }
        assertFails { Pbkdf2.withHmacSha512(password, salt, -1, 64) }
        assertFails { Pbkdf2.withHmacSha512(password, salt, 2048, 0) }
        assertFails { Pbkdf2.withHmacSha512(password, salt, 2048, -1) }
    }

    @Test
    fun `reject non-ascii passwords`() {
        val salt = "salt".encodeToByteArray()
        // The JVM implementation cannot compute the key when the password contains bytes greater than 0x7f: we reject
        // those passwords on every platform rather than accept them on some and silently return an invalid key on the JVM.
        assertFails { Pbkdf2.withHmacSha512(byteArrayOf(0x80.toByte()), salt, 2048, 64) }
        assertFails { Pbkdf2.withHmacSha512(byteArrayOf(0xff.toByte()), salt, 2048, 64) }
        assertFails { Pbkdf2.withHmacSha512("café".encodeToByteArray(), salt, 2048, 64) }
        // Non-english mnemonics are rejected as well, since they aren't ascii-encoded.
        val japanese = "あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あいこくしん あおぞら"
        assertFails { MnemonicCode.toSeed(japanese, "") }
    }

    @Test
    fun `accept ascii passwords`() {
        // Every byte of the 0x00-0x7f range is accepted, including 0x00.
        val password = ByteArray(0x80) { it.toByte() }
        assertEquals(
            "aa9f1e16011e1ef94b756b712419467c6c17d422515bba0048fae8707d9dce43eb9d376f9bbc1572d35add40f641bd0305684c74d0406d39712f5c636c12fe93",
            Hex.encode(Pbkdf2.withHmacSha512(password, "salt".encodeToByteArray(), 2048, 64))
        )
    }
}
