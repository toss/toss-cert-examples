package example;

import im.toss.cert.sdk.TossCertSession;
import im.toss.cert.sdk.TossCertSessionGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.RepeatedTest;

import java.util.Objects;
import java.util.Random;

import static example.JavaExample.*;
import static example.TestData.TEST_BASE64_PRIVATE_KEY;
import static example.TestData.TEST_BASE64_PUBLIC_KEY;
import static example.TestUtils.decryptSessionKey;

public class JavaExampleSdkTest {
    private static final TossCertSessionGenerator SESSION_GENERATOR = new TossCertSessionGenerator(TEST_BASE64_PUBLIC_KEY);

    @RepeatedTest(100)
    public void testGenerateSessionKey() throws Exception {
        SessionInfo sessionInfoFromSdk = new SessionInfo(SESSION_GENERATOR.generate());

        String sessionKey = generateSessionKey(sessionInfoFromSdk.sessionId, sessionInfoFromSdk.secretKey, sessionInfoFromSdk.iv, TEST_BASE64_PUBLIC_KEY);
        SessionInfo sessionInfoFromExample = new SessionInfo(sessionKey);

        System.out.println(sessionInfoFromExample);
        Assertions.assertEquals(sessionInfoFromSdk, sessionInfoFromExample);
    }

    @RepeatedTest(100)
    public void testEncryptDecryptData() throws Exception {
        TossCertSession session = SESSION_GENERATOR.generate();
        SessionInfo sessionInfo = new SessionInfo(session);

        String randomData = String.valueOf(new Random().nextLong());
        String encryptedDataBySdk = session.encrypt(randomData);
        String encryptedDataByExample = encryptData(sessionInfo.sessionId, sessionInfo.secretKey, sessionInfo.iv, randomData);

        System.out.println(encryptedDataByExample);
        Assertions.assertEquals(encryptedDataBySdk, encryptedDataByExample);

        String decryptedDataBySdk = session.decrypt(encryptedDataByExample);
        String decryptedDataByExample = decryptData(sessionInfo.secretKey, sessionInfo.iv, encryptedDataBySdk);

        System.out.println(decryptedDataByExample);
        Assertions.assertEquals(randomData, decryptedDataByExample);
        Assertions.assertEquals(decryptedDataBySdk, decryptedDataByExample);
    }

    public static class SessionInfo {
        public String version;
        public String sessionId;
        public String algorithm;
        public String secretKey;
        public String iv;

        public SessionInfo(TossCertSession session) throws Exception {
            this(session.getSessionKey());
        }

        public SessionInfo(String sessionKey) throws Exception {
            String[] fields = sessionKey.split("\\$");
            this.version = fields[0];
            this.sessionId = fields[1];

            String[] decryptedFields = decryptSessionKey(TEST_BASE64_PRIVATE_KEY, fields[2]).split("\\$");
            this.algorithm = decryptedFields[0];
            this.secretKey = decryptedFields[1];
            this.iv = decryptedFields[2];
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SessionInfo that = (SessionInfo) o;
            return Objects.equals(version, that.version) && Objects.equals(sessionId, that.sessionId) && Objects.equals(algorithm, that.algorithm) && Objects.equals(secretKey, that.secretKey) && Objects.equals(iv, that.iv);
        }

        @Override
        public String toString() {
            return "SessionInfo{" +
                    "version='" + version + '\'' +
                    ", sessionId='" + sessionId + '\'' +
                    ", algorithm='" + algorithm + '\'' +
                    ", secretKey='" + secretKey + '\'' +
                    ", iv='" + iv + '\'' +
                    '}';
        }
    }
}
