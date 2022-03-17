import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESEncryption {
    private static final String ENCRYPT_ALGO = "AES";
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();

    public static String encrypt(String original, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return encoder.encodeToString(cipher.doFinal(original.getBytes(UTF_8)));
    }

    public static String decrypt(String encrypted, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(decoder.decode(encrypted)));
    }
}