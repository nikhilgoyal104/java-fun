import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

class AESGCMEncryptionTest {
    @Test
    void testEncryptionAndDecryption() throws Exception {
        String original = "Amazon Ezetap Encryption Decryption Test";
        SecretKey secretKey = CryptoUtils.getAESKey();
        String encrypted = AESGCMEncryption.encrypt(original, secretKey);
        String decrypted = AESGCMEncryption.decrypt(encrypted, secretKey);
        assertEquals(original, decrypted);
    }
}