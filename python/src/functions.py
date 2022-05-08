import secrets

from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def b64encode_string(b):
    return b64encode(b).decode('utf-8')


def generate_random_bytes(length_in_bits):
    return b64encode_string(secrets.token_bytes(int(length_in_bits / 8)))


def generate_session_key(session_id, secret_key, iv, base64_public_key):
    session_aes_key = 'AES_GCM$' + secret_key + '$' + iv
    encrypted_session_aes_key = encrypt_session_aes_key(base64_public_key, session_aes_key)
    return 'v1$' + session_id + '$' + encrypted_session_aes_key


def encrypt_session_aes_key(base64_public_key, session_aes_key):
    public_key = RSA.importKey(b64decode(base64_public_key))

    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(session_aes_key.encode('utf-8'))
    return b64encode_string(encrypted)


def encrypt_data(session_id, secret_key, iv, data):
    cipher = AES.new(b64decode(secret_key), AES.MODE_GCM, b64decode(iv))
    cipher.update(b64decode(secret_key))

    encrypted, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    combined = b64encode_string(encrypted + tag)
    return 'v1$' + session_id + '$' + combined


def decrypt_data(secret_key, iv, encrypted_data):
    parsed = b64decode(encrypted_data.split('$')[2])
    encrypted = parsed[:len(parsed) - 16]
    tag = parsed[-16:]

    cipher = AES.new(b64decode(secret_key), AES.MODE_GCM, b64decode(iv))
    cipher.update(b64decode(secret_key))

    decrypted = cipher.decrypt_and_verify(encrypted, tag)
    return decrypted.decode('utf-8')
