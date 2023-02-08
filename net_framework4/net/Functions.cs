using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;

public class Functions
{
    public static string GenerateSessionId()
    {
        return Guid.NewGuid().ToString();
    }

    public static string GenerateRandomBytes(int length)
    {
        byte[] random = new byte[length];
        using (var randomGenerator = new RNGCryptoServiceProvider())
        {
            randomGenerator.GetNonZeroBytes(random);
        }
        return Convert.ToBase64String(random);
    }

    public static string GenerateSessionKey(string sessionId, string secretKey, string iv, string base64PublicKey)
    {
        string sessionAesKey = "AES_CBC$" + secretKey + "$" + iv;
        string encryptedSessionAesKey = EncryptSessionAesKey(base64PublicKey, sessionAesKey);
        return "v1$" + sessionId + "$" + encryptedSessionAesKey;
    }

    public static string EncryptSessionAesKey(string base64PublicKey, string sessionAesKey)
    {
        var rsaEngine = new OaepEncoding(new RsaEngine(), new Sha1Digest());
        var publicKey = (AsymmetricKeyParameter)PublicKeyFactory.CreateKey(Convert.FromBase64String(base64PublicKey));
        var sessionAesKeyBytes = Encoding.UTF8.GetBytes(sessionAesKey);
        rsaEngine.Init(true, publicKey);
        byte[] encrypted = rsaEngine.ProcessBlock(sessionAesKeyBytes, 0, sessionAesKeyBytes.Length);
        return Convert.ToBase64String(encrypted);
    }

    public static string EncryptData(string sessionId, string secretKey, string iv, string data)
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] ivBytes = Convert.FromBase64String(iv);
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);

        var cipher = CipherUtilities.GetCipher("AES/CBC/PKCS5Padding");
        var parameters = new ParametersWithIV(new KeyParameter(secretKeyBytes), ivBytes);
        cipher.Init(true, parameters);
        var cipherText = cipher.DoFinal(dataBytes);
        var hmacHex = HmacHash(secretKeyBytes, dataBytes);

        return "v1$" + sessionId + "$" + Convert.ToBase64String(cipherText) + "$" + hmacHex;
    }

    public static string DecryptData(string secretKey, string iv, string encryptedData)
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] ivBytes = Convert.FromBase64String(iv);

        string parsed = encryptedData.Split('$')[2];
        byte[] parsedBytes = Convert.FromBase64String(parsed);
        string hmac = encryptedData.Split('$')[3];

        var cipher = CipherUtilities.GetCipher("AES/CBC/PKCS5Padding");
        var parameters = new ParametersWithIV(new KeyParameter(secretKeyBytes), ivBytes);
        cipher.Init(false, parameters);
        var decrypted = cipher.DoFinal(parsedBytes);
        var hmacHex = HmacHash(secretKeyBytes, decrypted);
        if (hmac != hmacHex) throw new ArgumentException("HMAC 결과가 일치하지 않습니다.");
        return Encoding.UTF8.GetString(decrypted);
    }

    private static string HmacHash(byte[] secretKeyBytes, byte[] dataBytes)
    {
        using (var hmacsha256 = new HMACSHA256(secretKeyBytes))
        {
            var hash = hmacsha256.ComputeHash(dataBytes);
            return BitConverter.ToString(hash).Replace("-", string.Empty);
        }
    }
}
