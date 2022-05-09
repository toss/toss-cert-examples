require_relative '../src/functions'
require_relative 'test_data'

def assert_equals(expected, actual)
  if expected != actual
    puts 'Expected: ' + expected
    puts 'Actual: ' + actual
    raise Exception.new 'Assertion failed'
  end
end

def decrypt_session_key(base64_private_key_pkcs1, session_key)
  private_key = OpenSSL::PKey::RSA.new(Base64.strict_decode64(base64_private_key_pkcs1))

  decrypted = private_key.private_decrypt(Base64.strict_decode64(session_key), OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
  decrypted.force_encoding('UTF-8')
end

def test_decrypt_session_key
  RSA_TEST_DATA.each do |data|
    secret_key = data[1]
    iv = data[2]
    session_key = data[3]
    decrypted_session_key = decrypt_session_key(TEST_BASE64_PRIVATE_KEY_PKCS1, session_key.split('$')[2])

    puts decrypted_session_key
    assert_equals('AES_GCM$' + secret_key + '$' + iv, decrypted_session_key)
  end
end

def test_generate_session_key
  RSA_TEST_DATA.each do |data|
    session_id = data[0]
    secret_key = data[1]
    iv = data[2]
    session_key = data[3]
    generated_session_key = generate_session_key(session_id, secret_key, iv, TEST_BASE64_PUBLIC_KEY)
    decrypted_session_key = decrypt_session_key(TEST_BASE64_PRIVATE_KEY_PKCS1, generated_session_key.split('$')[2])

    puts generated_session_key
    puts decrypted_session_key

    assert_equals(session_key[0..39], generated_session_key[0..39])
    assert_equals('AES_GCM$' + secret_key + '$' + iv, decrypted_session_key)
  end
end

def test_encrypt_decrypt_data
  AES_TEST_DATA.each do |data|
    session_id = data[0]
    secret_key = data[1]
    iv = data[2]
    plain = data[3]
    encrypted = data[4]

    encrypted_data = encrypt_data(session_id, secret_key, iv, plain)
    decrypted_data = decrypt_data(secret_key, iv, encrypted)

    puts encrypted_data
    puts decrypted_data

    assert_equals(encrypted, encrypted_data)
    assert_equals(plain, decrypted_data)
  end
end