package example;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class Functions {

    public static String generateRandomBytes(int lengthInBits) {
        byte[] bytes = new byte[lengthInBits / 8];
        new SecureRandom().nextBytes(bytes);
        return Base64.encodeBase64String(bytes);
    }

    public static String generateSessionKey(String sessionId, String secretKey, String iv, String base64PublicKey) throws Exception {
        String sessionAesKey = "AES_GCM$" + secretKey + "$" + iv;
        String encryptedSessionAesKey = encryptSessionAesKey(base64PublicKey, sessionAesKey);
        return "v1$" + sessionId + "$" + encryptedSessionAesKey;
    }

    public static String encryptSessionAesKey(String base64PublicKey, String sessionAesKey) throws Exception {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decodeBase64(base64PublicKey)));

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = rsaCipher.doFinal(sessionAesKey.getBytes());
        return Base64.encodeBase64String(encrypted);
    }

    public static String encryptData(String sessionId, String secretKey, String iv, String data) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.decodeBase64(secretKey), "AES");
        AlgorithmParameterSpec ivSpec = new GCMParameterSpec(16 * Byte.SIZE, Base64.decodeBase64(iv));

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        aesCipher.updateAAD(secretKeySpec.getEncoded());

        byte[] encrypted = aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return "v1$" + sessionId + "$" + Base64.encodeBase64String(encrypted);
    }

    public static String decryptData(String secretKey, String iv, String encryptedData) throws Exception {
        String parsed = encryptedData.split("\\$")[2];

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.decodeBase64(secretKey), "AES");
        AlgorithmParameterSpec ivSpec = new GCMParameterSpec(16 * Byte.SIZE, Base64.decodeBase64(iv));

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        aesCipher.updateAAD(secretKeySpec.getEncoded());

        byte[] decrypted = aesCipher.doFinal(Base64.decodeBase64(parsed));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
