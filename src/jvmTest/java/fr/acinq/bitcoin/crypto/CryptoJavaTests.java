package fr.acinq.bitcoin.crypto;

import fr.acinq.secp256k1.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

public class CryptoJavaTests {

    @Test public void sha1() {
        final var bytes = Digest.sha1().hash("This is a test!".getBytes(StandardCharsets.UTF_8));
        final var hex = Hex.encode(bytes);
        assertEquals("8b6ccb43dca2040c3cfbcd7bfff0b387d4538c33", hex);
    }

    @Test public void sha256() {
        final var bytes = Digest.sha256().hash("This is a test!".getBytes(StandardCharsets.UTF_8));
        final var hex = Hex.encode(bytes);
        assertEquals("54ba1fdce5a89e0d3eee6e4c587497833bc38c3586ff02057dd6451fd2d6b640", hex);
    }

    @Test public void sha512() {
        final var bytes = Digest.sha512().hash("This is a test!".getBytes(StandardCharsets.UTF_8));
        final var hex = Hex.encode(bytes);
        assertEquals("d4d6331e89ced845639272bc64ca3ef4e94a57c88431c61aef91f4399e30c6ada32c042f72cedad9cb1c7cfaf04d92e06ad044b557ca16f554f1c6d66b06d0e0", hex);
    }

}
