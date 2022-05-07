using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Text;
using static TestData;

[TestClass]
public class NetExampleTest
{
    [TestMethod]
    public void TestDecryptSessionKey()
    {
        var secretKey = RSA_TEST_DATA[0, 1];
        var iv = RSA_TEST_DATA[0, 2];
        var sessionKey = RSA_TEST_DATA[0, 3];
        var decryptedSessionKey = DecryptSessionKey(TEST_BASE64_PRIVATE_KEY, sessionKey.Split('$')[2]);

        Console.WriteLine(decryptedSessionKey);
        AssertEquals("AES_GCM$" + secretKey + "$" + iv, decryptedSessionKey);
    }

    [TestMethod]
    public void TestGenerateSessionKey()
    {

    }

    [TestMethod]
    public void TestEncryptDecryptData()
    {

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
        var rsaCipher = RSA.Create();
        rsaCipher.ImportPkcs8PrivateKey(Convert.FromBase64String(base64PrivateKey), out _);

        byte[] decrypted = rsaCipher.Decrypt(Convert.FromBase64String(sessionKey), RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decrypted);
    }
}
