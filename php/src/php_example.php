<?php

require_once '../vendor/autoload.php';

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

main();

function main()
{
    /* ------------------------------ 1. 암복호화 키 생성 --------------------------- */
    $sessionId = uuid();
    $secretKey = generateKey(256);
    $iv = generateKey(128);

    /* ------------------------------ 2. 세션키 생성 ------------------------------- */

    // base64PublicKey 는 사전에 전달 받은 공개키 입니다.
    $base64PublicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoVdxG0Qi9pip46Jw9ImSlPVD8+L2mM47ey6EZna7D7utgNdh8Tzkjrm1Yl4h6kPJrhdWvMIJGS51+6dh041IXcJEoUquNblUEqAUXBYwQM8PdfnS12SjlvZrP4q6whBE7IV1SEIBJP0gSK5/8Iu+uld2ctJiU4p8uswL2bCPGWdvVPltxAg6hfAG/ImRUKPRewQsFhkFvqIDCpO6aeaR10q6wwENZltlJeeRnl02VWSneRmPqqypqCxz0Y+yWCYtsA+ngfZmwRMaFkXcWjaWnvSqqV33OAsrQkvuBHWoEEkvQ0P08+h9Fy2+FhY9TeuukQ2CVFz5YyOhp25QtWyQI+IaDKk+hLxJ1APR0c3tmV0ANEIjO6HhJIdu2KQKtgFppvqSrZp2OKtI8EZgVbWuho50xvlaPGzWoMi9HSCb+8ARamlOpesxHH3O0cTRUnft2Zk1FHQb2Pidb2z5onMEnzP2xpTqAIVQyb6nMac9tof5NFxwR/c4pmci+1n8GFJIFN18j2XGad1mNyio/R8LabqnzNwJC6VPnZJz5/pDUIk9yKNOY0KJe64SRiL0a4SNMohtyj6QlA/3SGxaEXb8UHpophv4G9wN1CgfyUamsRqp8zo5qDxBvlaIlfkqJvYPkltj7/23FHDjPi8q8UkSiAeu7IV5FTfB5KsiN8+sGSMCAwEAAQ==";

    // API 요청 파라미터에 넣어주세요.
    $sessionKey = generateSessionKey($sessionId, $secretKey, $iv, $base64PublicKey);
    echo "sessionKey: " . $sessionKey . "\n";

    /* ------------------------------ 3. 개인정보 암호화 ----------------------------- */

    $userName = "김토스";
    $encryptedUserName = encryptData($sessionId, $secretKey, $iv, $userName); // 암호화된 개인 정보
    echo "encryptedUserName: " . $encryptedUserName . "\n";

    /* ------------------------------ 4. 개인정보 복호화 ----------------------------- */

    // 응답을 받은 경우, 요청을 보낼 때 생성했던 secretKey, iv 를 가지고 있어야 합니다.
    // encryptedUserName 이 응답 받은 암호화된 userName 이라고 가정합니다.
    $decryptedUserName = decryptData($secretKey, $iv, $encryptedUserName);
    echo "decryptedUserName: " . $decryptedUserName . "\n";

    /* ------------------------------ 5. 암복호화 결과 검증 --------------------------- */

    if ($decryptedUserName != $userName) {
        echo "암복호화 결과가 일치하지 않습니다." . "\n";
    }
}

function uuid(): string
{
    $data = random_bytes(16);

    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function generateKey(int $aesKeyBitLength): string
{
    return base64_encode(random_bytes($aesKeyBitLength / 8));
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
        ->withHash('sha256')
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