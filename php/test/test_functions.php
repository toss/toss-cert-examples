<?php

require_once '../vendor/autoload.php';

require_once "../src/functions.php";
require_once "test_data.php";

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

function testDecryptSessionKey()
{
    global $RSA_TEST_DATA;
    global $TEST_BASE64_PRIVATE_KEY;

    for ($i = 1; $i <= 3; $i++) {
        $data = $RSA_TEST_DATA[array_rand($RSA_TEST_DATA)];

        $secretKey = $data[1];
        $iv = $data[2];
        $sessionKey = $data[3];
        $decryptedSessionKey = decryptSessionKey($TEST_BASE64_PRIVATE_KEY, explode('$', $sessionKey)[2]);

        echo $decryptedSessionKey . "\n";
        assertEquals('AES_GCM$' . $secretKey . '$' . $iv, $decryptedSessionKey);
    }
}

function testGenerateSessionKey()
{
    global $RSA_TEST_DATA;
    global $TEST_BASE64_PUBLIC_KEY;
    global $TEST_BASE64_PRIVATE_KEY;

    for ($i = 1; $i <= 3; $i++) {
        $data = $RSA_TEST_DATA[array_rand($RSA_TEST_DATA)];

        $sessionId = $data[0];
        $secretKey = $data[1];
        $iv = $data[2];
        $sessionKey = $data[3];
        $generatedSessionKey = generateSessionKey($sessionId, $secretKey, $iv, $TEST_BASE64_PUBLIC_KEY);
        $decryptedSessionKey = decryptSessionKey($TEST_BASE64_PRIVATE_KEY, explode('$', $generatedSessionKey)[2]);

        echo $generatedSessionKey . "\n";
        echo $decryptedSessionKey . "\n";

        assertEquals(substr($sessionKey, 0, 40), substr($generatedSessionKey, 0, 40));
        assertEquals('AES_GCM$' . $secretKey . '$' . $iv, $decryptedSessionKey);
    }
}

function testEncryptDecryptData()
{
    global $AES_TEST_DATA;

    foreach ($AES_TEST_DATA as $data) {
        $sessionId = $data[0];
        $secretKey = $data[1];
        $iv = $data[2];
        $plain = $data[3];
        $encrypted = $data[4];

        $encryptedData = encryptData($sessionId, $secretKey, $iv, $plain);
        $decryptedData = decryptData($secretKey, $iv, $encrypted);

        echo $encryptedData . "\n";
        echo $decryptedData . "\n";

        assertEquals($encrypted, $encryptedData);
        assertEquals($plain, $decryptedData);
    }
}

function assertEquals($expected, $actual)
{
    if ($expected != $actual) {
        echo "Expected: " . $expected . "\n";
        echo "Actual: " . $actual . "\n";
        throw new RuntimeException("Assertion failed");
    }
}

function decryptSessionKey(string $base64PrivateKey, string $sessionKey): string
{
    $rsa = PublicKeyLoader::load($base64PrivateKey)
        ->withPadding(RSA::ENCRYPTION_OAEP)
        ->withHash('sha1')
        ->withMGFHash('sha1');

    return $rsa->decrypt(base64_decode($sessionKey));
}