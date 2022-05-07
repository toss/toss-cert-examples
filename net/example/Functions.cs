using System;
using System.Security.Cryptography;
using System.Text;

public class Functions
{
    public static string GenerateRandomBytes(int lengthInBits)
    {
        byte[] random = new byte[lengthInBits / 8];
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
        var rsaCipher = new RSACryptoServiceProvider();
        rsaCipher.ImportRSAPublicKey(Convert.FromBase64String(base64PublicKey), out _);

        byte[] encrypted = rsaCipher.Encrypt(Encoding.UTF8.GetBytes(sessionAesKey), RSAEncryptionPadding.OaepSHA1);
        return Encoding.UTF8.GetString(encrypted);
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
