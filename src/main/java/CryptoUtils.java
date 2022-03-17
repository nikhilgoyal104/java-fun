import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class CryptoUtils {
    public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static SecretKey getAESKey() {
        return new SecretKeySpec("amazon_ezetap_10".getBytes(StandardCharsets.UTF_8), "AES");
    }
}
