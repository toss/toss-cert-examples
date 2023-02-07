using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Modes;
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
        string sessionAesKey = "AES_GCM$" + secretKey + "$" + iv;
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

        var aead = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(secretKeyBytes), 128, ivBytes);
        aead.Init(true, parameters);
        byte[] encrypted = new byte[aead.GetOutputSize(dataBytes.Length)];
        int len = aead.ProcessBytes(dataBytes, 0, dataBytes.Length, encrypted, 0);
        aead.DoFinal(encrypted, len);

        return "v1$" + sessionId + "$" + Convert.ToBase64String(encrypted);
    }

    public static string DecryptData(string secretKey, string iv, string encryptedData)
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] ivBytes = Convert.FromBase64String(iv);

        string parsed = encryptedData.Split('$')[2];
        byte[] parsedBytes = Convert.FromBase64String(parsed);

        var aead = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(secretKeyBytes), 128, ivBytes);
        aead.Init(false, parameters);
        byte[] decrypted = new byte[aead.GetOutputSize(parsedBytes.Length)];
        var decLen = aead.ProcessBytes(parsedBytes, 0, parsedBytes.Length, decrypted, 0);
        aead.DoFinal(decrypted, decLen);
        return Encoding.UTF8.GetString(decrypted);
    }
}
