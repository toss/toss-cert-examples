from Crypto.IO import PKCS8

from src.functions import *
from test_data import *


def assert_equals(expected, actual):
    if expected != actual:
        print('Expected: ' + expected)
        print('Actual: ' + actual)
        raise Exception('Assertion failed')


def decrypt_session_key(base64_private_key, session_key):
    private_key = RSA.importKey(PKCS8.unwrap(b64decode(base64_private_key))[1])

    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(b64decode(session_key))
    return decrypted.decode('utf-8')


def test_decrypt_session_key():
    for data in RSA_TEST_DATA:
        secret_key = data[1]
        iv = data[2]
        session_key = data[3]
        decrypted_session_key = decrypt_session_key(TEST_BASE64_PRIVATE_KEY, session_key.split('$')[2])

        print(decrypted_session_key)
        assert_equals('AES_GCM$' + secret_key + '$' + iv, decrypted_session_key)


def test_generate_session_key():
    for data in RSA_TEST_DATA:
        session_id = data[0]
        secret_key = data[1]
        iv = data[2]
        session_key = data[3]
        generated_session_key = generate_session_key(session_id, secret_key, iv, TEST_BASE64_PUBLIC_KEY)
        decrypted_session_key = decrypt_session_key(TEST_BASE64_PRIVATE_KEY, generated_session_key.split('$')[2])

        print(generated_session_key)
        print(decrypted_session_key)

        assert_equals(session_key[:40], generated_session_key[:40])
        assert_equals('AES_GCM$' + secret_key + '$' + iv, decrypted_session_key)


def test_encrypt_decrypt_data():
    for data in AES_TEST_DATA:
        session_id = data[0]
        secret_key = data[1]
        iv = data[2]
        plain = data[3]
        encrypted = data[4]

        encrypted_data = encrypt_data(session_id, secret_key, iv, plain)
        decrypted_data = decrypt_data(secret_key, iv, encrypted)

        print(encrypted_data)
        print(decrypted_data)

        assert_equals(encrypted, encrypted_data)
        assert_equals(plain, decrypted_data)
