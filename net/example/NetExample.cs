using System;
using System.Security.Cryptography;
using System.Text;

class NetExample
{
    static void Main(string[] args)
    {
        /* ------------------------------ 1. 암복호화 키 생성 --------------------------- */

        string sessionId = Guid.NewGuid().ToString();
        string secretKey = GenerateKey(256);
        string iv = GenerateKey(96);

        /* ------------------------------ 2. 세션키 생성 ------------------------------- */

        // base64PublicKey 는 사전에 전달 받은 공개키 입니다.
        String base64PublicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoVdxG0Qi9pip46Jw9ImSlPVD8+L2mM47ey6EZna7D7utgNdh8Tzkjrm1Yl4h6kPJrhdWvMIJGS51+6dh041IXcJEoUquNblUEqAUXBYwQM8PdfnS12SjlvZrP4q6whBE7IV1SEIBJP0gSK5/8Iu+uld2ctJiU4p8uswL2bCPGWdvVPltxAg6hfAG/ImRUKPRewQsFhkFvqIDCpO6aeaR10q6wwENZltlJeeRnl02VWSneRmPqqypqCxz0Y+yWCYtsA+ngfZmwRMaFkXcWjaWnvSqqV33OAsrQkvuBHWoEEkvQ0P08+h9Fy2+FhY9TeuukQ2CVFz5YyOhp25QtWyQI+IaDKk+hLxJ1APR0c3tmV0ANEIjO6HhJIdu2KQKtgFppvqSrZp2OKtI8EZgVbWuho50xvlaPGzWoMi9HSCb+8ARamlOpesxHH3O0cTRUnft2Zk1FHQb2Pidb2z5onMEnzP2xpTqAIVQyb6nMac9tof5NFxwR/c4pmci+1n8GFJIFN18j2XGad1mNyio/R8LabqnzNwJC6VPnZJz5/pDUIk9yKNOY0KJe64SRiL0a4SNMohtyj6QlA/3SGxaEXb8UHpophv4G9wN1CgfyUamsRqp8zo5qDxBvlaIlfkqJvYPkltj7/23FHDjPi8q8UkSiAeu7IV5FTfB5KsiN8+sGSMCAwEAAQ==";

        // API 요청 파라미터에 넣어주세요.
        String sessionKey = GenerateSessionKey(sessionId, secretKey, iv, base64PublicKey);
        Console.WriteLine("sessionKey: " + sessionKey);

        /* ------------------------------ 3. 개인정보 암호화 ----------------------------- */

        String userName = "김토스";
        String encryptedUserName = EncryptData(sessionId, secretKey, iv, userName); // 암호화된 개인 정보
        Console.WriteLine("encryptedUserName: " + encryptedUserName);

        /* ------------------------------ 4. 개인정보 복호화 ----------------------------- */

        // 응답을 받은 경우, 요청을 보낼 때 생성했던 secretKey, iv 를 가지고 있어야 합니다.
        // encryptedUserName 이 응답 받은 암호화된 userName 이라고 가정합니다.
        String decryptedUserName = DecryptData(secretKey, iv, encryptedUserName);
        Console.WriteLine("decryptedUserName: " + decryptedUserName);

        /* ------------------------------ 5. 암복호화 결과 검증 --------------------------- */

        if (decryptedUserName != userName)
        {
            Console.Error.WriteLine("암복호화 결과가 일치하지 않습니다.");
        }
    }

    public static string GenerateKey(int aesKeyBitLength)
    {
        byte[] random = new byte[aesKeyBitLength / 8];

        using var randomGenerator = new RNGCryptoServiceProvider();
        randomGenerator.GetNonZeroBytes(random);
        return Convert.ToBase64String(random);
    }

    public static string GenerateSessionKey(string sessionId, string secretKey, string iv, string base64PublicKey)
    {
        string sessionAesKey = "AES_GCM$" + secretKey + "$" + iv;
        string encryptedSessionAesKey = EncryptSessionAesKey(base64PublicKey, sessionAesKey);
        return "v1$" + sessionId + "$" + encryptedSessionAesKey;
    }

    public static string EncryptSessionAesKey(string base64PublicKey, string sessionAesKey)
    {
        return "";
    }

    public static string EncryptData(string sessionId, string secretKey, string iv, string data)
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] ivBytes = Convert.FromBase64String(iv);

        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
        byte[] encrypted = new byte[dataBytes.Length];
        byte[] tag = new byte[16];

        using var aesCipher = new AesGcm(secretKeyBytes);
        aesCipher.Encrypt(ivBytes, dataBytes, encrypted, tag, secretKeyBytes);

        byte[] combined = new byte[encrypted.Length + tag.Length];
        Buffer.BlockCopy(encrypted, 0, combined, 0, encrypted.Length);
        Buffer.BlockCopy(tag, 0, combined, encrypted.Length, tag.Length);

        return "v1$" + sessionId + "$" + Convert.ToBase64String(combined); ;
    }

    public static string DecryptData(string secretKey, string iv, string encryptedData)
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] ivBytes = Convert.FromBase64String(iv);

        string parsed = encryptedData.Split('$')[2];
        byte[] parsedBytes = Convert.FromBase64String(parsed);

        byte[] encrypted = new byte[parsedBytes.Length - 16];
        Buffer.BlockCopy(parsedBytes, 0, encrypted, 0, parsedBytes.Length - 16);

        byte[] decrypted = new byte[parsedBytes.Length - 16];
        byte[] tag = new byte[16];
        Buffer.BlockCopy(parsedBytes, parsedBytes.Length - 16, tag, 0, 16);

        using var aesCipher = new AesGcm(secretKeyBytes);
        aesCipher.Decrypt(ivBytes, encrypted, tag, decrypted, secretKeyBytes);

        return Encoding.UTF8.GetString(decrypted);
    }
}
