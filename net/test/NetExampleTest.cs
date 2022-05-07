using System;
using System.Security.Cryptography;
using System.Text;

using static TestData;
using static Functions;

class NetExampleTest
{
    static void Main(string[] args)
    {
        TestDecryptSessionKey();
        TestGenerateSessionKey();
        TestEncryptDecryptData();
    }

    public static void TestDecryptSessionKey()
    {
        for (int i = 0; i < RSA_TEST_DATA.GetLength(0); i++)
        {
            var secretKey = RSA_TEST_DATA[i, 1];
            var iv = RSA_TEST_DATA[i, 2];
            var sessionKey = RSA_TEST_DATA[i, 3];
            var decryptedSessionKey = DecryptSessionKey(TEST_BASE64_PRIVATE_KEY, sessionKey.Split('$')[2]);

            Console.WriteLine(decryptedSessionKey);
            AssertEquals("AES_GCM$" + secretKey + "$" + iv, decryptedSessionKey);
        }
    }

    public static void TestGenerateSessionKey()
    {
        for (int i = 0; i < RSA_TEST_DATA.GetLength(0); i++)
        {
            var sessionId = RSA_TEST_DATA[i, 0];
            var secretKey = RSA_TEST_DATA[i, 1];
            var iv = RSA_TEST_DATA[i, 2];
            var sessionKey = RSA_TEST_DATA[i, 3];
            var generatedSessionKey = GenerateSessionKey(sessionId, secretKey, iv, TEST_BASE64_PUBLIC_KEY);
            var decryptedSessionKey = DecryptSessionKey(TEST_BASE64_PRIVATE_KEY, sessionKey.Split('$')[2]);

            Console.WriteLine(generatedSessionKey);
            Console.WriteLine(decryptedSessionKey);

            AssertEquals(sessionKey.Substring(0, 40), generatedSessionKey.Substring(0, 40));
            AssertEquals("AES_GCM$" + secretKey + "$" + iv, decryptedSessionKey);
        }
    }

    public static void TestEncryptDecryptData()
    {
        for (int i = 0; i < AES_TEST_DATA.GetLength(0); i++)
        {
            var sessionId = AES_TEST_DATA[i, 0];
            var secretKey = AES_TEST_DATA[i, 1];
            var iv = AES_TEST_DATA[i, 2];
            var plain = AES_TEST_DATA[i, 3];
            var encrypted = AES_TEST_DATA[i, 4];

            String encryptedData = EncryptData(sessionId, secretKey, iv, plain);
            String decryptedData = DecryptData(secretKey, iv, encrypted);

            Console.WriteLine(encryptedData);
            Console.WriteLine(decryptedData);

            AssertEquals(encrypted, encryptedData);
            AssertEquals(plain, decryptedData);
        }
    }

    public static void AssertEquals(string expected, string actual)
    {
        if (expected != actual)
        {
            Console.Error.WriteLine("Expected: " + expected);
            Console.Error.WriteLine("Actual: " + actual);
            throw new SystemException("Assertion failed");
        }
    }

    public static string DecryptSessionKey(string base64PrivateKey, string sessionKey)
    {
        var rsaCipher = new RSACryptoServiceProvider();
        rsaCipher.ImportPkcs8PrivateKey(Convert.FromBase64String(base64PrivateKey), out _);

        byte[] decrypted = rsaCipher.Decrypt(Convert.FromBase64String(sessionKey), RSAEncryptionPadding.OaepSHA1);
        return Encoding.UTF8.GetString(decrypted);
    }
}
