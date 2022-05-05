package example;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static example.JavaExample.generateSessionKey;
import static example.TestData.*;
import static example.TestUtils.decryptSessionKey;

public class JavaExampleRsaTest {

    @Test
    public void testDecryptSessionKey() throws Exception {
        for (String[] data : SESSION_KEY_DATA) {
            String secretKey = data[1];
            String iv = data[2];
            String sessionKey = data[3];
            String decrypted = decryptSessionKey(TEST_BASE64_PRIVATE_KEY, sessionKey.split("\\$")[2]);

            System.out.println(decrypted);
            Assertions.assertEquals("AES_GCM$" + secretKey + "$" + iv, decrypted);
        }
    }

    @Test
    public void testGenerateSessionKey() throws Exception {
        for (String[] data : SESSION_KEY_DATA) {
            String sessionId = data[0];
            String secretKey = data[1];
            String iv = data[2];
            String sessionKey = data[3];
            String generatedSessionKey = generateSessionKey(sessionId, secretKey, iv, TEST_BASE64_PUBLIC_KEY);
            String decrypted = decryptSessionKey(TEST_BASE64_PRIVATE_KEY, generatedSessionKey.split("\\$")[2]);

            System.out.println(generatedSessionKey);
            System.out.println(decrypted);

            Assertions.assertEquals(sessionKey.substring(0, 40), generatedSessionKey.substring(0, 40));
            Assertions.assertEquals("AES_GCM$" + secretKey + "$" + iv, decrypted);
        }
    }
}
