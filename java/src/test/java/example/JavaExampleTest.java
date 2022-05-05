package example;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static example.JavaExample.*;
import static example.TestData.*;
import static example.TestUtils.decryptSessionKey;

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
            String sessionKey = data[0];
            String plain = data[1];
            String encrypted = data[2];

            String sessionId = sessionKey.split("\\$")[1];
            String[] decryptedSessionFields = decryptSessionKey(TEST_BASE64_PRIVATE_KEY, sessionKey.split("\\$")[2]).split("\\$");
            String secretKey = decryptedSessionFields[1];
            String iv = decryptedSessionFields[2];

            String encryptedData = encryptData(sessionId, secretKey, iv, plain);
            String decryptedData = decryptData(secretKey, iv, encrypted);

            System.out.println(encryptedData);
            System.out.println(decryptedData);

            Assertions.assertEquals(encrypted, encryptedData);
            Assertions.assertEquals(plain, decryptedData);
        }
    }
}
