package fr.acinq.bitcoin.crypto;

import fr.acinq.secp256k1.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

public class Pbkdf2JavaTests {

    @Test public void withHmacSha512() {
        final var password =
                Hex.decode("6162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e206162616e646f6e2061626f7574");
        final var salt = Hex.decode("6d6e656d6f6e6963");
        final var result = Pbkdf2.withHmacSha512(password, salt, 2048, 64);
        assertEquals("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4", Hex.encode(result));
    }

}
