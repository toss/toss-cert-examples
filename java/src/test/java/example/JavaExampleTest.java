package example;

import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import static example.Functions.*;
import static example.TestData.*;

public class JavaExampleTest {

    @Test
    public void testDecryptSessionKey() throws Exception {
        for (String[] data : RSA_TEST_DATA) {
            String secretKey = data[1];
            String iv = data[2];
            String sessionKey = data[3];
            String decryptedSessionKey = decryptSessionKey(TEST_BASE64_PRIVATE_KEY, sessionKey.split("\\$")[2]);

            System.out.println(decryptedSessionKey);
            Assertions.assertEquals("AES_GCM$" + secretKey + "$" + iv, decryptedSessionKey);
        }
    }

    @Test
    public void testGenerateSessionKey() throws Exception {
        for (String[] data : RSA_TEST_DATA) {
            String sessionId = data[0];
            String secretKey = data[1];
            String iv = data[2];
            String sessionKey = data[3];
            String generatedSessionKey = generateSessionKey(sessionId, secretKey, iv, TEST_BASE64_PUBLIC_KEY);
            String decryptedSessionKey = decryptSessionKey(TEST_BASE64_PRIVATE_KEY, generatedSessionKey.split("\\$")[2]);

            System.out.println(generatedSessionKey);
            System.out.println(decryptedSessionKey);

            Assertions.assertEquals(sessionKey.substring(0, 40), generatedSessionKey.substring(0, 40));
            Assertions.assertEquals("AES_GCM$" + secretKey + "$" + iv, decryptedSessionKey);
        }
    }

    @Test
    public void testEncryptDecryptData() throws Exception {
        for (String[] data : AES_TEST_DATA) {
            String sessionId = data[0];
            String secretKey = data[1];
            String iv = data[2];
            String plain = data[3];
            String encrypted = data[4];

            String encryptedData = encryptData(sessionId, secretKey, iv, plain);
            String decryptedData = decryptData(secretKey, iv, encrypted);

            System.out.println(encryptedData);
            System.out.println(decryptedData);

            Assertions.assertEquals(encrypted, encryptedData);
            Assertions.assertEquals(plain, decryptedData);
        }
    }

    public static String decryptSessionKey(String base64PrivateKey, String sessionKey) throws Exception {
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.decodeBase64(base64PrivateKey)));

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decrypted = cipher.doFinal(Base64.decodeBase64(sessionKey.getBytes()));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
