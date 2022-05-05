<?php

require_once '../vendor/autoload.php';
include "test_data.php";

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

testDecryptSessionKey();

function testDecryptSessionKey()
{
    global $RSA_TEST_DATA;
    global $TEST_BASE64_PRIVATE_KEY;

    $data = $RSA_TEST_DATA[0];

    $secretKey = $data[1];
    $iv = $data[2];
    $sessionKey = $data[3];
    echo $secretKey, "\n";
    echo $iv, "\n";
    echo $sessionKey, "\n";
    echo explode('$', $sessionKey)[2], "\n";
    // echo base64_decode(explode('$', $sessionKey)[2]);

    $decryptedSessionKey = decryptSessionKey($TEST_BASE64_PRIVATE_KEY, explode('$', $sessionKey)[2]);
    echo $decryptedSessionKey . "\n";

//    foreach ($RSA_TEST_DATA as $data) {
//
//    }
}

function decryptSessionKey(string $base64PrivateKey, string $sessionKey): string
{
    $rsa = PublicKeyLoader::load($base64PrivateKey)->withPadding(RSA::ENCRYPTION_OAEP);
    return $rsa->decrypt(base64_decode($sessionKey));
}