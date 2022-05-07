<?php

require_once '../vendor/autoload.php';

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

function uuid(): string
{
    $data = random_bytes(16);

    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function generateRandomBytes(int $lengthInBits): string
{
    return base64_encode(random_bytes($lengthInBits / 8));
}

function generateSessionKey(string $sessionId, string $secretKey, string $iv, string $base64PublicKey): string
{
    $sessionAesKey = "AES_GCM$" . $secretKey . "$" . $iv;
    $encryptedSessionAesKey = encryptSessionAesKey($base64PublicKey, $sessionAesKey);
    return "v1$" . $sessionId . "$" . $encryptedSessionAesKey;
}

function encryptSessionAesKey(string $base64PublicKey, string $sessionAesKey): string
{
    $rsa = PublicKeyLoader::load($base64PublicKey)
        ->withPadding(RSA::ENCRYPTION_OAEP)
        ->withHash('sha1')
        ->withMGFHash('sha1');

    $bytePlain = $rsa->encrypt($sessionAesKey);
    return base64_encode($bytePlain);
}

function encryptData(string $sessionId, string $secretKey, string $iv, string $data): string
{
    $cipher = new AES('gcm');
    $cipher->setKey(base64_decode($secretKey));
    $cipher->setNonce(base64_decode($iv));
    $cipher->setAAD(base64_decode($secretKey));

    $encrypted = base64_encode($cipher->encrypt($data) . $cipher->getTag());
    return 'v1$' . $sessionId . '$' . $encrypted;
}

function decryptData(string $secretKey, string $iv, string $encryptedData): string
{
    $parsed = base64_decode(explode('$', $encryptedData)[2]);

    $cipher = new AES('gcm');
    $cipher->setKey(base64_decode($secretKey));
    $cipher->setNonce(base64_decode($iv));
    $cipher->setAAD(base64_decode($secretKey));
    $cipher->setTag(substr($parsed, strlen($parsed) - 16));

    return $cipher->decrypt(substr($parsed, 0, strlen($parsed) - 16));
}