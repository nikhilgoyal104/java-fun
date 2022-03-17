import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class AESGCMEncryption {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();

    public static String encrypt(String original, SecretKey secretKey) throws Exception {
        byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);
        System.out.println("Random Generated IV->" + Arrays.toString(iv));
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        cipher.updateAAD(iv);
        byte[] cipherText = cipher.doFinal(original.getBytes(UTF_8));
        return encoder.encodeToString(ByteBuffer
            .allocate(iv.length + cipherText.length)
            .put(iv)
            .put(cipherText)
            .array());
    }

    public static String decrypt(String encrypted, SecretKey secretKey) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(decoder.decode(encrypted));
        byte[] iv = new byte[IV_LENGTH_BYTE];
        byteBuffer.get(iv);
        System.out.println("Extracted IV during decryption->" + Arrays.toString(iv));
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        cipher.updateAAD(iv);
        return new String(cipher.doFinal(cipherText));
    }
}
