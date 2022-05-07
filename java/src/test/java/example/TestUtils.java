package example;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class TestUtils {

    public static String decryptSessionKey(String base64PrivateKey, String sessionKey) throws Exception {
        byte[] decodedBase64PvtKey = Base64.decodeBase64(base64PrivateKey);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedBase64PvtKey));
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = rsaCipher.doFinal(Base64.decodeBase64(sessionKey.getBytes()));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
