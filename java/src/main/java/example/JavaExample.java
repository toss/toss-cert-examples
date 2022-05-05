package example;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

public class JavaExample {

    public static void main(String[] args) throws Exception {
        /* ------------------------------ 1. 암복호화 키 생성 --------------------------- */

        String sessionId = UUID.randomUUID().toString();
        String secretKey = generateKey(256);
        String iv = generateKey(128);

        /* ------------------------------ 2. 세션키 생성 ------------------------------- */

        // base64PublicKey 는 사전에 전달 받은 공개키 입니다.
        String base64PublicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoVdxG0Qi9pip46Jw9ImSlPVD8+L2mM47ey6EZna7D7utgNdh8Tzkjrm1Yl4h6kPJrhdWvMIJGS51+6dh041IXcJEoUquNblUEqAUXBYwQM8PdfnS12SjlvZrP4q6whBE7IV1SEIBJP0gSK5/8Iu+uld2ctJiU4p8uswL2bCPGWdvVPltxAg6hfAG/ImRUKPRewQsFhkFvqIDCpO6aeaR10q6wwENZltlJeeRnl02VWSneRmPqqypqCxz0Y+yWCYtsA+ngfZmwRMaFkXcWjaWnvSqqV33OAsrQkvuBHWoEEkvQ0P08+h9Fy2+FhY9TeuukQ2CVFz5YyOhp25QtWyQI+IaDKk+hLxJ1APR0c3tmV0ANEIjO6HhJIdu2KQKtgFppvqSrZp2OKtI8EZgVbWuho50xvlaPGzWoMi9HSCb+8ARamlOpesxHH3O0cTRUnft2Zk1FHQb2Pidb2z5onMEnzP2xpTqAIVQyb6nMac9tof5NFxwR/c4pmci+1n8GFJIFN18j2XGad1mNyio/R8LabqnzNwJC6VPnZJz5/pDUIk9yKNOY0KJe64SRiL0a4SNMohtyj6QlA/3SGxaEXb8UHpophv4G9wN1CgfyUamsRqp8zo5qDxBvlaIlfkqJvYPkltj7/23FHDjPi8q8UkSiAeu7IV5FTfB5KsiN8+sGSMCAwEAAQ==";

        // API 요청 파라미터에 넣어주세요.
        String sessionKey = generateSessionKey(sessionId, secretKey, iv, base64PublicKey);

        /* ------------------------------ 3. 개인정보 암호화 ----------------------------- */

        String userName = "소중한 개인정보 입니다";
        String encryptedUserName = encryptData(sessionId, secretKey, iv, userName); // 암호화된 개인 정보
        System.out.println("encryptedUserName: " + encryptedUserName);

        /* ------------------------------ 4. 개인정보 복호화 ----------------------------- */

        // 응답을 받은 경우, 요청을 보낼 때 생성했던 secretKey, iv 를 가지고 있어야 합니다.
        // encryptedUserName 이 응답 받은 암호화된 userName 이라고 가정합니다.
        String decryptedUserName = decryptData(secretKey, iv, encryptedUserName);
        System.out.println("decryptedUserName: " + decryptedUserName);

        /* ------------------------------ 5. 암복호화 결과 검증 --------------------------- */

        if (!decryptedUserName.equals(userName)) {
            System.err.println("암복호화 결과가 일치하지 않습니다.");
        }
    }

    public static String generateKey(int aesKeyBitLength) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(aesKeyBitLength, new SecureRandom());
        return Base64.encodeBase64String(keyGenerator.generateKey().getEncoded());
    }

    public static String generateSessionKey(String sessionId, String secretKey, String iv, String base64PublicKey) throws Exception {
        String sessionAesKey = "AES_GCM" + "$" + secretKey + "$" + iv;
        String encryptedSessionAesKey = encryptSessionAesKey(base64PublicKey, sessionAesKey);
        return "v1$" + sessionId + "$" + encryptedSessionAesKey;
    }

    public static String encryptSessionAesKey(String base64PublicKey, String sessionAesKey) throws Exception {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decodeBase64(base64PublicKey)));

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytePlain = rsaCipher.doFinal(sessionAesKey.getBytes());
        return Base64.encodeBase64String(bytePlain);
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