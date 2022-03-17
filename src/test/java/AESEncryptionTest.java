import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

class AESEncryptionTest {
    @Test
    void testEncryptionAndDecryption() throws Exception {
        String original = "Amazon Ezetap Encryption Decryption Test";
        SecretKey secretKey = CryptoUtils.getAESKey();
        String encrypted = AESEncryption.encrypt(original, secretKey);
        String decrypted = AESEncryption.decrypt(encrypted, secretKey);
        assertEquals(original, decrypted);
    }
}